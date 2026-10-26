package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/tokhive/tee/cmd/internal/shared"
	"github.com/tokhive/tee/hub"
	"github.com/tokhive/tee/jobs"
	"github.com/tokhive/tee/policy"
	"github.com/tokhive/tee/proof"
	"github.com/tokhive/tee/tee"
)

// defaultRequestReadTimeout bounds how long a client may take to send a whole
// request — request line, headers, and body — before the Hub gives up on it.
//
// ReadHeaderTimeout alone does not cover this: it stops a client that stalls in
// the headers, but a client that sends headers promptly and then dribbles (or
// never sends) the body it announced with Content-Length keeps a connection and
// its goroutine for as long as it likes. The 16 MiB body cap bounds how much can
// arrive, not how slowly.
//
// It is safe to set server-wide precisely because it bounds *reading the
// request* and nothing else. The stdlib clears the read deadline once the body
// is consumed (and on hijack, which is how the agent gate and the tee relay take
// the connection), so a response that streams for minutes — every SSE answer —
// is untouched; it is WriteTimeout, deliberately left zero, that would cut such
// a stream. The value is generous because a request body may legitimately be
// large and the client's uplink is not the Hub's to choose; the point is that it
// is finite.
const defaultRequestReadTimeout = 30 * time.Second

// serveConfig is the routing the resident service hands to the scheduler: the
// upstream it asks the TEE to reach.
type serveConfig struct {
	Addr string // where the Hub listens for its users
	Host string // the default AI service host:port (must be admitted by the deployment policy)
	// ProviderHosts overrides Host for the named providers. A deployment serves
	// every model from one host in the simulation, but a real deployment fronts
	// several vendors' endpoints, and one seller's token is only good at its
	// own vendor: HostFor (below) is what every spec-framing site uses, so a
	// provider absent from the map is served at Host and nothing else changes.
	ProviderHosts map[string]string
	Query         string // extra upstream query (fault injection, for the harness)
	Max           uint64 // MaxResponseBytes cap passed to the TEE. For a request it caps the body; for a session it caps the downlink, so the session settles for what it delivered instead of being cut un-reconcilably by the Hub
	// SessionPath is the upstream WebSocket path a streaming session is relayed
	// to. Empty means /v1/realtime. It is a deployment knob, not user input: the
	// policy whitelists this path and the admission check below judges agents on
	// it, so a deployment fronting a provider whose realtime endpoint lives
	// elsewhere configures it once and both halves agree.
	SessionPath string
	Tenants     tenantResolver
	// Policy is the deployment whitelist. The Hub advertises it on /v1/policies
	// and admits every dialing agent against it, so buyers and sellers see
	// exactly the whitelist the enclave enforces (the same bundle bytes on an
	// SNP instance) and a request refused by policy is a fact either could have
	// checked up front. Nil means the whitelist was unavailable at startup:
	// the endpoint says so, and no agent is admitted.
	Policy *policy.Policy
}

// HostFor returns the upstream host:port jobs for provider are framed with:
// the per-provider override when one is configured, otherwise the Hub-wide
// default. A zero ProviderHosts map keeps the old behavior (everything to
// Host), so single-upstream deployments and existing tests need no changes.
func (c serveConfig) HostFor(provider string) string {
	if h, ok := c.ProviderHosts[provider]; ok {
		return h
	}
	return c.Host
}

// upstreamSessionPath returns the path a session's Upgrade targets: the
// configured override when one is set, otherwise the built-in realtime path.
func (c serveConfig) upstreamSessionPath() string {
	if c.SessionPath != "" {
		return c.SessionPath
	}
	return realtimePath
}

// tenantKeyHeader is the header a user presents to identify itself. It is the
// Hub's user-facing counterpart to the agent gate's key header: a bearer
// credential, held to the same rule (a mismatch is refused, never defaulted).
const tenantKeyHeader = "X-TokenHive-Key"

// tenantResolver maps a presented user key to the tenant it belongs to, which
// is what quota and attribution key on.
//
// With a key map configured, only a provisioned key admits a request and the
// tenant is the mapped name — the caller cannot choose who it is. Without one
// the Hub runs open: the presented key is the tenant, which is the deliberate
// dev stance (there is no provisioned identity to check against), but the key
// is still required. Silently defaulting an absent key to one shared name would
// make every headerless caller a single tenant — one shared quota bucket and
// one indistinguishable attribution — which is worse than refusing them.
type tenantResolver struct {
	// keys maps a user API key to the tenant it authenticates as. Empty means
	// open mode.
	keys map[string]string
}

// resolve returns the tenant a request belongs to, and whether it may proceed.
func (r tenantResolver) resolve(req *http.Request) (string, bool) {
	key := req.Header.Get(tenantKeyHeader)
	if key == "" {
		return "", false
	}
	if len(r.keys) == 0 {
		return key, true
	}
	tenant, ok := r.keys[key]
	return tenant, ok
}

// userRoute describes one user-facing endpoint the Hub relays. The Hub is a
// byte relay, not a format translator: a request's body travels upstream
// unchanged and the upstream's response bytes come back unchanged. The
// difference between routes is which upstream path they address and whether
// the user-visible stream needs an OpenAI-style [DONE] terminator appended.
type userRoute struct {
	// Path is both the user-facing path and the upstream provider path. The
	// connection-resident data path keys providers by policy, and the policy
	// whitelists exactly this path — so which providers may answer a route is
	// decided by the providers' own signed policies, not by the Hub.
	Path string
	// Done appends "data: [DONE]\n\n" after a successful relay. OpenAI
	// chat-completions streams terminate with this marker; Anthropic streams
	// terminate with their own event: message_stop, and OpenAI Responses
	// streams end with the response.completed event, so those routes leave the
	// upstream's framing alone.
	Done bool
}

// userRoutes is the Hub's user-facing API surface. Every route is a byte
// relay of the same shape — read the body, let the model field drive provider
// selection, forward the bytes upstream, stream the upstream's bytes back —
// and differs only in which provider path it addresses and whether the
// user-visible stream needs an OpenAI chat-style [DONE] appended.
//
// The three formats are served verbatim, not translated:
//   - /v1/chat/completions  (OpenAI Chat Completions)  — terminator: [DONE]
//   - /v1/messages          (Anthropic Messages)       — terminator: message_stop
//   - /v1/responses         (OpenAI Responses)         — terminator: response.completed
//
// All three carry the model name in the JSON body's top-level "model" field,
// which is the only part the Hub reads; the rest of the request travels
// untouched, and the response bytes the user sees are exactly the bytes the
// provider produced.
var userRoutes = []userRoute{
	{Path: "/v1/chat/completions", Done: true},
	{Path: "/v1/messages", Done: false},
	{Path: "/v1/responses", Done: false},
}

// agentGatePath and teeRelayPath are the Hub's reverse-tunnel endpoints: the
// AgentGate a Provider Agent dials to come online, and the TeeRelay the TEE
// dials to carry egress across those tunnels. Mounting them is what turns the
// Hub into the rendezvous point for NAT-trapped contributors.
const (
	agentGatePath     = "/v1/agent"
	teeRelayPath      = "/v1/relay"
	credentialKeyPath = "/v1/credential-key"
	modelsPath        = "/v1/models"
	policiesPath      = "/v1/policies"
)

var relayUpgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

// runServe exposes the Hub as a resident OpenAI-compatible HTTP service. It
// blocks until the server stops.
//
// Unlike the one-shot CLI (which pins a provider), this is the product shape:
// a user submits a request and the Hub decides which provider serves it,
// cheapest first, re-emitting the provider's stream to the user.
func runServe(h *hub.Hub, cfg serveConfig) {
	mux := http.NewServeMux()
	for _, route := range userRoutes {
		mux.Handle(route.Path, &userHandler{h: h, cfg: cfg, route: route})
	}
	mux.Handle(sessionPath, &sessionHandler{h: h, cfg: cfg})
	mux.Handle(agentGatePath, h.AgentGate(relayUpgrader))
	mux.Handle(teeRelayPath, h.TeeRelay(relayUpgrader))
	mux.HandleFunc(credentialKeyPath, h.CredentialKeyHandler)
	mux.HandleFunc(modelsPath, modelsHandler(h))
	mux.HandleFunc(policiesPath, policiesHandler(cfg.Policy))
	log.Printf("hub user-facing API listening on http://%s%v (sessions at %s, models at %s, policies at %s)",
		cfg.Addr, routePaths(), sessionPath, modelsPath, policiesPath)
	log.Printf("hub reverse-tunnel endpoints: agent gate %s, tee relay %s, credential key %s",
		agentGatePath, teeRelayPath, credentialKeyPath)
	srv := newHubServer(cfg.Addr, mux, defaultRequestReadTimeout)
	log.Fatal(srv.ListenAndServe())
}

// newHubServer builds the Hub's HTTP server. It is split out so a test can run
// the real configuration with its own read timeout — a test cannot wait out the
// shipped 30s to observe the bound.
//
// WriteTimeout stays zero on purpose: an SSE response has no bounded size or
// duration, and a write deadline would cut a live stream mid-body. ReadTimeout
// is set because it bounds only the read side of a request, which the stdlib
// ends before the handler runs (see defaultRequestReadTimeout).
func newHubServer(addr string, handler http.Handler, readTimeout time.Duration) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       readTimeout,
		IdleTimeout:       120 * time.Second,
	}
}

func routePaths() []string {
	paths := make([]string, len(userRoutes))
	for i, route := range userRoutes {
		paths[i] = route.Path
	}
	return paths
}

// userHandler implements one user-facing endpoint. The request body is
// forwarded byte-for-byte to the TEE (bound by BodyHash), but the model field
// is read out first because it drives provider selection.
type userHandler struct {
	h     *hub.Hub
	cfg   serveConfig
	route userRoute
}

func (c *userHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		// A body that stopped arriving is the deadline the server set (see
		// defaultRequestReadTimeout) expiring: the client stalled, which is a
		// 408. Any other read failure is a body the Hub cannot use, which is a
		// 400.
		if errors.Is(err, os.ErrDeadlineExceeded) {
			writeJSONError(w, http.StatusRequestTimeout, "request body timed out")
			log.Printf("api path=%s err=body read timeout", c.route.Path)
			return
		}
		writeJSONError(w, http.StatusBadRequest, "read body")
		return
	}
	var req struct {
		Model    string `json:"model"`
		Provider string `json:"provider,omitempty"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Model == "" {
		writeJSONError(w, http.StatusBadRequest, "model is required")
		return
	}

	// Tenant resolution: the caller identifies itself with a key, which either
	// resolves through the Hub's key map to its tenant or (in open mode) is the
	// tenant. A request with no key, or a key the map does not hold, is refused
	// before anything is dispatched.
	tenant, ok := c.cfg.Tenants.resolve(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "missing or invalid api key")
		log.Printf("api model=%q path=%s err=unauthorized", req.Model, c.route.Path)
		return
	}

	flusher, _ := w.(http.Flusher)

	// The user-visible status and headers are committed from the TEE's
	// response-start frame, not from the first relayed byte: the Hub must know
	// whether the upstream answered 200 or 401/429 before it shows the buyer
	// anything. Dispatch failures that happen before any start (unknown model,
	// quota, no serving provider) return a proper JSON error with a
	// meaningful status instead.
	var (
		started bool
		status  int
	)
	commit := func(resp tee.Response) {
		if started {
			return
		}
		started = true
		status = int(resp.StatusCode)
		if status == 0 {
			// No response start (an exchange that never produced a response):
			// fall back to the streaming default, as before.
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		// The upstream's relayed headers override the defaults: a 401 JSON
		// error keeps its application/json, a 200 stream keeps its
		// text/event-stream. Del-then-Add replaces the default value rather
		// than appending a second one, while still preserving a multi-value
		// upstream header.
		for name, values := range resp.Headers {
			w.Header().Del(name)
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(status)
	}
	isSuccess := func() bool { return status >= 200 && status < 300 }

	var chunks int
	onChunk := func(chunk []byte) error {
		// The chunk is already the upstream's SSE bytes — mockprovider
		// frames `data: {…}` and the data path relays raw body bytes, so
		// re-wrapping here would emit `data: data: {…}` and break every
		// OpenAI SDK. The Hub's only job is byte-pass-through.
		commit(tee.Response{})
		if _, werr := w.Write(chunk); werr != nil {
			return werr
		}
		chunks++
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}
	var outcome hub.Outcome
	if req.Provider != "" {
		outcome, err = c.h.ExecuteForProvider(r.Context(), tenant, req.Model, req.Provider, body,
			func(provider string) (jobs.Spec, error) {
				return shared.BuildSpec(provider, c.cfg.HostFor(provider), c.route.Path, c.cfg.Query, body, c.cfg.Max)
			}, onChunk, commit)
	} else {
		outcome, err = c.h.ExecuteForModel(r.Context(), tenant, req.Model, body,
			func(provider string) (jobs.Spec, error) {
				return shared.BuildSpec(provider, c.cfg.HostFor(provider), c.route.Path, c.cfg.Query, body, c.cfg.Max)
			}, onChunk, commit)
	}
	if !started {
		// Nothing was committed to the wire: either a dispatch failure, or
		// every provider failed before its response began and the last attempt
		// came back as a verified failure receipt with no Go error (status
		// zero, no bytes). Both must reach the buyer as a proper error — an
		// empty implicit 200 would say "succeeded" with no body and no SSE
		// content type.
		if err == nil {
			err = errors.New("no provider produced a response")
		}
		writeJSONError(w, apiErrorStatus(err), err.Error())
		log.Printf("api model=%q path=%s tenant=%q err=%v failure=%v", req.Model, c.route.Path, tenant, err, outcome.Failure)
		return
	}
	// A committed 2xx stream is a success only when the receipt says the
	// upstream completed it. A provider that answered 200 and then died
	// mid-body — crash, reset, timeout after the first byte, or the TEE's own
	// byte cap — is attested as CompletionTruncated and priced at zero. Ending
	// such a stream with [DONE] would present a partial answer as a finished
	// one, so on the routes that fabricate the terminator the truncation is
	// reported like any committed failure and the marker is withheld.
	truncated := err == nil && isSuccess() &&
		outcome.Receipt.Receipt.Completion != proof.CompletionComplete
	if err != nil {
		// The response is committed. For a 2xx stream the failure is reported
		// as an SSE error frame; for a non-2xx upstream status the upstream's
		// own error body already tells the story, and splicing an SSE frame
		// into it would corrupt the error the buyer is reading. Either way
		// nothing settles: hub.Execute returned no verified receipt to settle
		// against, so the failure is logged and the response ends here.
		if isSuccess() {
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", sseError(err))
		}
	}
	if c.route.Done && truncated {
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", sseError(errors.New("upstream response ended before completion")))
	}
	if c.route.Done && isSuccess() && !truncated {
		// OpenAI-compatible chat streams terminate with an explicit done marker,
		// which the mock upstream does not emit. Appended after an error frame
		// too, so a client that started reading a 2xx stream is never left
		// waiting for a terminator that cannot come. Never appended to a
		// non-2xx response, whose body is the complete error already. An
		// upstream that completed with an empty body still needs the marker,
		// hence the commit here.
		commit(tee.Response{})
		fmt.Fprint(w, "data: [DONE]\n\n")
	}
	if started && flusher != nil {
		flusher.Flush()
	}

	log.Printf("api model=%q path=%s tenant=%q provider=%q status=%d chunks=%d charged=%.2f commission=%.2f buyer=%.2f failure=%v err=%v",
		req.Model, c.route.Path, tenant, outcome.Receipt.Receipt.Provider, status, chunks,
		float64(outcome.Charged)/microsPerUnit, float64(outcome.Commission)/microsPerUnit,
		float64(outcome.Buyer)/microsPerUnit, outcome.Failure, err)
}

// modelsHandler answers GET /v1/models: the buyer-facing market directory.
//
// The endpoint exposes two views. The default is the model-aggregated
// directory: each model an online agent declared it can serve appears once, at
// the lowest current per-request book price. The optional ?q= query filters
// that view by a case-insensitive substring of the model name, so a buyer can
// look up an exact model or scan a family ("deepseek" returns every
// deepseek-* listing).
//
// Two declarations switch to the expanded market view, where the same model
// served by two sources appears as two rows:
//
//	?provider=NAME      every model one source offers
//	?model=NAME         every source offering a model (substring)
//
// A buyer who names no source gets the cheapest server by default; one who
// names a source — either to survey it or to pin a request to it — gets that
// source's rows.
func modelsHandler(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		provider, model := query.Get("provider"), query.Get("model")
		var quotes []hub.ModelQuote
		switch {
		case provider != "" || model != "":
			quotes = h.MarketQuotes(provider, model)
		case query.Get("q") != "":
			quotes = h.SearchModels(query.Get("q"))
		default:
			quotes = h.ModelDirectory()
		}
		if quotes == nil {
			quotes = []hub.ModelQuote{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Models []hub.ModelQuote `json:"models"`
		}{Models: quotes})
	}
}

// policiesHandler answers GET /v1/policies: the deployment whitelist a buyer or
// seller can check up front, without asking the TEE. It mirrors the /v1/models
// directory — a read-only view of deployment config, not an execution path.
//
// The response is the one document the enclave runs with: the hosts it may
// reach, the request families permitted on them, and its hash
// (TokenHive.Policy.v1 over the canonical encoding). A buyer who pins the hash
// can spot a rotated whitelist; a seller can confirm the whitelist it is
// admitted under. There is no per-provider view to ask for, because there is no
// per-provider policy.
//
// The policy is nil only when it could not be loaded; the endpoint says so
// rather than inventing a whitelist the enclave did not run with.
func policiesHandler(p *policy.Policy) http.HandlerFunc {
	type ruleView struct {
		Methods       []string `json:"methods"`
		Path          string   `json:"path"`
		AllowStream   bool     `json:"allow_stream,omitempty"`
		QueryKeys     []string `json:"query_keys,omitempty"`
		AllowAnyQuery bool     `json:"allow_any_query,omitempty"`
	}
	type policyView struct {
		Hosts            []string   `json:"hosts"`
		Rules            []ruleView `json:"rules"`
		MaxResponseBytes uint64     `json:"max_response_bytes"`
		MaxBodyBytes     uint64     `json:"max_body_bytes"`
		AllowedHeaders   []string   `json:"allowed_headers"`
		IssuedAt         int64      `json:"issued_at"`
		ExpiresAt        int64      `json:"expires_at"`
	}
	type response struct {
		PolicyHash  string      `json:"policy_hash"`
		Policy      *policyView `json:"policy"`
		Unavailable bool        `json:"unavailable,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		out := response{}
		if p == nil {
			out.Unavailable = true
		} else {
			if h, err := p.Hash(); err == nil {
				out.PolicyHash = hex.EncodeToString(h[:])
			}
			view := &policyView{
				Hosts:            p.Hosts,
				Rules:            make([]ruleView, 0, len(p.Rules)),
				MaxResponseBytes: p.Limits.MaxResponseBytes,
				MaxBodyBytes:     p.Limits.MaxBodyBytes,
				AllowedHeaders:   p.Limits.AllowedHeaders,
				IssuedAt:         p.IssuedAt,
				ExpiresAt:        p.ExpiresAt,
			}
			for _, rule := range p.Rules {
				view.Rules = append(view.Rules, ruleView{
					Methods:       rule.Methods,
					Path:          rule.Path,
					AllowStream:   rule.AllowStream,
					QueryKeys:     rule.QueryKeys,
					AllowAnyQuery: rule.AllowAnyQuery,
				})
			}
			out.Policy = view
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// admitAgainstPolicy is the deployment's admission check for a dialing agent.
//
// A seller chooses what it charges and which models it declares; it does not get
// to choose what the enclave will accept. So before an agent becomes
// schedulable the Hub looks up, by host and path, whether the deployment is
// willing to reach the upstream this agent's jobs will egress to. That upstream
// is per-provider — the agent's own host from the Hub's routing (a
// -provider-hosts override when one is configured, otherwise the Hub-wide
// -host) — because one seller's token is only good at its own vendor. An agent
// whose models could only be served on a path the whitelist does not cover
// would otherwise be scheduled and then refused inside the TEE — a refusal the
// seller never sees the reason for. Refusing at bring-up says so where the
// seller is standing.
//
// The whole route surface is checked, because a buyer picks the route and the
// Hub picks the seller: a model is only really admitted if the deployment admits
// every surface it could be asked for on.
func admitAgainstPolicy(p *policy.Policy, hostFor func(string) string, sessionPath string) func(hub.AgentRegister) error {
	return func(reg hub.AgentRegister) error {
		if p == nil {
			return fmt.Errorf("no deployment policy loaded: refusing agent %q", reg.Provider)
		}
		host := hostFor(reg.Provider)
		type route struct{ path, method string }
		routes := []route{{sessionPath, http.MethodGet}}
		for _, r := range userRoutes {
			routes = append(routes, route{r.Path, http.MethodPost})
		}
		for _, r := range routes {
			if err := p.AllowsRoute(host, r.path, r.method); err != nil {
				return fmt.Errorf("agent %q: upstream %s%s is not admitted: %w",
					reg.Provider, host, r.path, err)
			}
		}
		return nil
	}
}

// apiErrorStatus maps a dispatch failure to an HTTP status. A provider that
// simply cannot serve the model is a 404; a market with every agent offline
// is a 503 (the model may exist — the supply is what is down); quota
// exhaustion and an exceeded in-flight share are both 429 (the request was
// fine, the tenant is already asking for as much as it may), and an exhausted
// spend budget is a 402 (refusing on price is not the same complaint as
// refusing on rate); anything else is a 502 upstream failure.
func apiErrorStatus(err error) int {
	switch {
	case errors.Is(err, hub.ErrNoProviderForModel), errors.Is(err, hub.ErrUnknownProvider):
		return http.StatusNotFound
	case errors.Is(err, hub.ErrNoProvidersOnline):
		return http.StatusServiceUnavailable
	case errors.Is(err, hub.ErrBudgetExceeded):
		return http.StatusPaymentRequired
	case errors.Is(err, hub.ErrQuotaExceeded), errors.Is(err, hub.ErrTooManyInflight):
		return http.StatusTooManyRequests
	default:
		return http.StatusBadGateway
	}
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"error":{"message":%q}}`, msg)
}

// sseError renders an error safely for a one-line SSE data field.
func sseError(err error) string {
	return strings.ReplaceAll(err.Error(), "\n", " ")
}

// sessionPath is the user-facing streaming-session endpoint. A user opens a
// WebSocket here, the Hub learns the model from the first frame, selects the
// cheapest provider, and relays the full-duplex session through the TEE.
//
// realtimePath is the default upstream path that session is relayed to; a
// deployment may override it with serveConfig.SessionPath. The two differ — the
// session is a Hub-shaped endpoint in front of a provider-shaped one — so the
// whitelist is written against the upstream path while the route is mounted at
// sessionPath, and the admission check below names both explicitly rather than
// deriving one from the other.
const (
	sessionPath  = "/v1/session"
	realtimePath = "/v1/realtime"
)

// sessionUpgrader upgrades the user's HTTP request to a WebSocket. Origin is
// unrestricted — the consumer is an API key holder, not a browser, so there is
// no origin header to police; the trust gate is the tenant header, exactly like
// the request routes.
//
// No extension is enabled: permessage-deflate would wrap the provider-facing
// byte stream in a codec the TEE refuses to negotiate, so the Upgrader declines
// it and the client speaks plain frames (which every client does when the
// server declines).
var sessionUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(*http.Request) bool { return true },
}

// Keepalive and write bounds for the user-facing half of a session.
//
// A session can legitimately sit quiet for minutes, so silence alone must not
// end it; the Hub probes both peers and treats an unanswered probe as a dead
// connection. The upstream ping interval must stay well under the TEE's idle
// watchdog (SessionIdleTimeout), because that ping is also what keeps a quiet
// session alive inside the enclave instead of being reaped mid-conversation.
const (
	sessionPingInterval = 30 * time.Second
	sessionPongWait     = 75 * time.Second
	userWriteWait       = 10 * time.Second
)

// sessionHandler serves the streaming-session endpoint. It is the session
// counterpart of userHandler: read the model out of the first frame, let the
// scheduler pick the provider, relay the bytes, settle. The user's frames travel
// byte-for-byte; only the model field of the first frame is ever examined.
type sessionHandler struct {
	h   *hub.Hub
	cfg serveConfig
}

func (c *sessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authentication is an HTTP-header gate, so it is answered before the
	// Upgrade: an unauthorized caller gets a normal 401 instead of a WebSocket
	// that opens and immediately dies.
	tenant, ok := c.cfg.Tenants.resolve(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "missing or invalid api key")
		return
	}

	// Subprotocol negotiation. The Hub answers the user's handshake with
	// exactly the client's first offer and asks the provider for that same
	// protocol, so the user's own handshake is never a lie. If the provider
	// selects anything else, RunRealtime refuses the session before a byte
	// moves (see hub.ErrSessionProtocolMismatch).
	upg := sessionUpgrader
	offered := websocket.Subprotocols(r)
	if len(offered) > 0 {
		upg.Subprotocols = []string{offered[0]}
	}
	conn, err := upg.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	// Bound every user frame the relay reads (first frame and the uplink stream)
	// so a hostile client cannot blow the Hub's memory with an oversized message.
	conn.SetReadLimit(hub.MaxWSMessageBytes)
	// Liveness: only a pong (or a delivered message) extends the read
	// deadline, so a client that vanishes without a close frame is noticed
	// instead of pinning the uplink goroutine for the life of the process.
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(sessionPongWait))
	})

	// The first frame is read here so the model can drive provider selection,
	// then handed back to the link, which replays it to the provider — reading
	// it costs the provider nothing and the bytes still travel unchanged.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	mt, first, err := conn.ReadMessage()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	var req struct {
		Model    string `json:"model"`
		Provider string `json:"provider,omitempty"`
	}
	if err := json.Unmarshal(first, &req); err != nil || req.Model == "" {
		// The Upgrade has already been answered, so a bare return would look to
		// the user like a transport fault. Say what was wrong instead.
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "first frame must name a model"),
			time.Now().Add(userWriteWait))
		return
	}

	link := &sessionLink{
		conn:        conn,
		first:       first,
		firstOp:     frameOpcode(mt),
		subprotocol: conn.Subprotocol(),
	}
	build := func(provider string) (jobs.Spec, error) {
		return c.buildSession(provider, link.subprotocol)
	}

	var outcome hub.SessionOutcome
	if req.Provider != "" {
		outcome, err = c.h.RunRealtimeForProvider(r.Context(), tenant, req.Model, req.Provider, build, link)
	} else {
		outcome, err = c.h.RunRealtime(r.Context(), tenant, req.Model, build, link)
	}
	// Give the user an orderly close either way: an error carries a reason, and a
	// clean end that the provider did not itself close (a dropped socket after
	// its last message) becomes a normal closure rather than a bare TCP teardown
	// that reads like a network fault.
	link.finish(err)
	log.Printf("session model=%q tenant=%q provider=%q uplink=%d downlink=%d charged=%.2f commission=%.2f buyer=%.2f err=%v",
		req.Model, tenant, outcome.Provider, outcome.UplinkBytes, outcome.DownlinkBytes,
		float64(outcome.Charged)/microsPerUnit, float64(outcome.Commission)/microsPerUnit,
		float64(outcome.Buyer)/microsPerUnit, err)
}

// buildSession frames the session spec for a provider. Identical across providers
// except the provider name, exactly as buildSpec frames request specs.
//
// subprotocol is the one the user's handshake settled on (empty for none). It
// travels as an ordinary header, because the TEE writes the provider's Upgrade
// from the spec's headers; the TEE's handshake check then returns what the
// provider selected so the two ends can be reconciled.
func (c *sessionHandler) buildSession(provider, subprotocol string) (jobs.Spec, error) {
	jobID := make([]byte, jobs.JobIDLength)
	if _, err := rand.Read(jobID); err != nil {
		return jobs.Spec{}, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return jobs.Spec{}, err
	}
	headers := map[string]string{}
	if subprotocol != "" {
		headers["sec-websocket-protocol"] = subprotocol
	}
	return jobs.Spec{
		Version:          jobs.VersionV1,
		JobID:            jobID,
		Provider:         provider,
		Method:           "GET",
		Host:             c.cfg.HostFor(provider),
		Path:             c.cfg.upstreamSessionPath(),
		Query:            c.cfg.Query,
		Headers:          headers,
		BodyHash:         shared.BodyHash(nil),
		Nonce:            nonce,
		ExpiresAt:        time.Now().Add(time.Hour).Unix(),
		MaxResponseBytes: c.cfg.Max,
		Stream:           true,
		Session:          true,
	}, nil
}

// sessionLink adapts the user WebSocket to the Hub's RealtimeLink seam. Read
// yields the user's uplink — the first frame is replayed so the model read out
// of it still reaches the provider — and Write delivers the provider's downlink.
//
// The TEE tunnel is a transparent byte pipe that relays payload bytes verbatim;
// WebSocket frame semantics are the Hub's business, so this adapter owns them
// on both directions:
//
//   - Uplink: the user WebSocket driver (gorilla) already strips the user's
//     frame, leaving a raw payload. A provider's parser, however, expects a legal
//     masked client frame, so Read re-wraps each payload in one before it is
//     handed to the tunnel. The frame is laid out once and handed out in pieces
//     across Read calls, because a 16 MiB message is routinely larger than the
//     relay's 32 KiB buffer.
//   - Downlink: the tunnel yields the provider's raw server frames (possibly
//     split or bundled across tunnel messages, possibly fragmented), so Write
//     decodes them and re-emits each reassembled data message to the user.
//   - Control plane: the provider's pings are answered through the tunnel (the
//     TEE relays the pong like any other uplink byte), the provider's close is
//     forwarded to the user, and a user that ends — close frame or broken
//     socket — sends a close frame upstream so the provider finishes its side
//     and the TEE can still sign the receipt. This is the whole reason a user
//     hanging up first does not forfeit the session.
//
// Like the TEE tunnel it is a full-duplex pipe: the Hub relays the two directions
// on separate goroutines, so the user socket is locked per direction and never
// across a blocking read (which would deadlock the session).
type sessionLink struct {
	conn        *websocket.Conn
	subprotocol string

	readMu  sync.Mutex // serializes the uplink reader (one reader only)
	writeMu sync.Mutex // serializes the downlink writer (one writer only)

	// mu guards the fields below; the wire I/O happens after releasing it.
	mu        sync.Mutex
	first     []byte // the first user message, replayed to the provider
	firstOp   byte   // that message's frame opcode
	pending   []byte // masked bytes still to hand out
	readErr   error
	writesOff bool // no more frames may be written to the user
	tunnel    io.Writer
	keepStop  chan struct{}
	keepDone  chan struct{}

	// down frames the incoming provider (server) frame stream. Only the downlink
	// writer touches it, so it is guarded by writeMu.
	down *hub.WsFrameDecoder
}

// Subprotocol implements hub.SessionProtocol: the protocol negotiated with the
// user, which the provider's handshake must match.
func (l *sessionLink) Subprotocol() string { return l.subprotocol }

// BindSession implements hub.SessionLinkBinder. relaySession calls it once,
// before either direction starts, with the metered writer every tunnel byte must
// go through.
func (l *sessionLink) BindSession(tunnel io.Writer) {
	l.mu.Lock()
	l.tunnel = tunnel
	stop := make(chan struct{})
	done := make(chan struct{})
	l.keepStop = stop
	l.keepDone = done
	l.mu.Unlock()
	// The first read deadline starts here: the session may now run for as long
	// as the user keeps answering.
	_ = l.conn.SetReadDeadline(time.Now().Add(sessionPongWait))
	go l.keepalive(stop, done)
}

// ReleaseSession implements hub.SessionLinkBinder, stopping the keepalive so it
// cannot outlive the relay.
//
// It waits for the keepalive goroutine to finish, not merely signals it: a probe
// already past its select may still be writing into the tunnel, and the relay
// reconciles the receipt's RequestBytes against the tunnel's write count right
// after this returns. Letting that write land afterwards would count a byte the
// receipt attests but the Hub had not yet counted — a mismatch that forfeits a
// session whose bytes were all delivered.
func (l *sessionLink) ReleaseSession() {
	l.mu.Lock()
	stop, done := l.keepStop, l.keepDone
	l.keepStop, l.keepDone = nil, nil
	l.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	if done != nil {
		<-done
	}
}

// keepalive probes both peers on an interval.
//
// The user probe is a WebSocket ping the client's library answers on its own;
// its pong extends the read deadline (see the handler in sessionHandler), which
// is how a vanished client is detected. The provider probe is a masked ping
// written into the tunnel: it elicits a pong from the provider and, just as
// importantly, is uplink traffic the TEE's idle watchdog sees, so a quiet but
// healthy conversation is not reaped inside the enclave.
func (l *sessionLink) keepalive(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(sessionPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			_ = l.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(userWriteWait))
			l.writeTunnelFrame(hub.WSOpPing, nil)
		}
	}
}

// Read returns the next provider-bound chunk: a legal masked client frame built
// from the user's message (or the replayed first frame). The bytes are exactly
// what the provider's own parser must accept, and they are handed out in pieces
// when the frame is larger than p.
func (l *sessionLink) Read(p []byte) (int, error) {
	l.readMu.Lock()
	defer l.readMu.Unlock()
	for {
		l.mu.Lock()
		if len(l.pending) > 0 {
			n := copy(p, l.pending)
			l.pending = l.pending[n:]
			l.mu.Unlock()
			return n, nil
		}
		if l.readErr != nil {
			err := l.readErr
			l.mu.Unlock()
			return 0, err
		}
		// Pull one raw payload out of first (the message already read for model
		// selection), then frame it below.
		var payload []byte
		var op byte
		if len(l.first) > 0 {
			payload = l.first
			l.first = nil
			op = l.firstOp
			if op != hub.WSOpBinary {
				op = hub.WSOpText
			}
		} else {
			l.mu.Unlock()
			mt, msg, err := l.conn.ReadMessage()
			if err != nil {
				l.mu.Lock()
				l.readErr = err
				l.mu.Unlock()
				// The user's side is over. Send a close frame upstream so the
				// provider ends its stream and the TEE can still sign the
				// receipt — an abandoned tunnel would forfeit the session — and
				// stop writing to a socket that has already said goodbye.
				l.closeUpstream(err)
				l.stopUserWrites()
				return 0, err
			}
			_ = l.conn.SetReadDeadline(time.Now().Add(sessionPongWait))
			l.mu.Lock()
			payload = msg
			op = hub.WSOpText
			if mt == websocket.BinaryMessage {
				op = hub.WSOpBinary
			}
		}
		l.pending = hub.MaskClientFrame(op, payload)
		l.mu.Unlock()
	}
}

func frameOpcode(mt int) byte {
	if mt == websocket.BinaryMessage {
		return hub.WSOpBinary
	}
	return hub.WSOpText
}

// Write consumes a tunnel downlink chunk (raw provider frames), decodes it, and
// re-emits each reassembled data message to the user as a fresh WebSocket
// message. It returns len(p) because every byte fed in is accounted for: a
// close frame stops delivery but the bytes that carried it still count toward
// the transcript the receipt attests.
func (l *sessionLink) Write(p []byte) (int, error) {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	if l.down == nil {
		l.down = hub.NewWsFrameDecoder()
	}
	frames, derr := l.down.Feed(p)
	for _, f := range frames {
		switch f.Opcode {
		case hub.WSOpText, hub.WSOpBinary:
			if l.userWritesOff() {
				continue
			}
			msgType := websocket.TextMessage
			if f.Opcode == hub.WSOpBinary {
				msgType = websocket.BinaryMessage
			}
			_ = l.conn.SetWriteDeadline(time.Now().Add(userWriteWait))
			if werr := l.conn.WriteMessage(msgType, f.Data); werr != nil {
				// The user socket is no longer writable, so it is no longer
				// deliverable in either direction. Mark it so the close handshake
				// does not try to write to a broken socket, and report the failure
				// while still accounting for every byte this chunk consumed.
				l.stopUserWrites()
				return len(p), werr
			}
		case hub.WSOpPing:
			// A provider that pings is waiting for its pong before its own
			// deadline. The pong is a tunnel byte like any other, so it goes
			// through the metered writer.
			l.writeTunnelFrame(hub.WSOpPong, f.Data)
		case hub.WSOpPong:
			// The provider's answer to our keepalive; nothing to relay.
		case hub.WSOpClose:
			code, reason, ok := hub.ParseClosePayload(f.Data)
			if !ok {
				code, reason = websocket.CloseProtocolError, "invalid close frame from provider"
			}
			l.sendCloseLocked(int(code), reason)
		}
	}
	if derr != nil {
		// The provider spoke a broken frame stream; give the user a protocol
		// close instead of leaving them waiting on a session that cannot go on.
		l.sendCloseLocked(websocket.CloseProtocolError, "provider sent a malformed websocket stream")
		return len(p), derr
	}
	return len(p), nil
}

// CloseSession implements hub.SessionCloser: the Hub is ending the session on
// its own terms (an upload bound), so both ends get a close handshake. The
// provider's answer is what lets the TEE finish and sign the receipt.
func (l *sessionLink) CloseSession(reason string) {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	l.writeTunnelFrame(hub.WSOpClose, hub.ClosePayload(websocket.ClosePolicyViolation, reason))
	l.sendCloseLocked(websocket.ClosePolicyViolation, reason)
}

// finish closes the user-facing socket with a reason once the session is over.
//
// A clean end that did not itself forward a provider close — a provider that
// simply dropped its TCP connection after its last message — gets a normal
// close, so the user reads an orderly end rather than an unexplained transport
// failure. An error gets an internal-error close with a reason the user can
// observe; a bare TCP teardown after a successful Upgrade looks like a network
// fault, not a refused session. It is a no-op after any earlier close, so the
// user's own close and a forwarded provider close win.
func (l *sessionLink) finish(err error) {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	if err == nil {
		l.sendCloseLocked(websocket.CloseNormalClosure, "")
		return
	}
	reason := "session failed"
	if errors.Is(err, hub.ErrSessionProtocolMismatch) {
		reason = "provider did not accept the negotiated subprotocol"
	}
	l.sendCloseLocked(websocket.CloseInternalServerErr, reason)
}

// sendCloseLocked writes one close frame to the user and marks the user side
// unwritable. Caller holds writeMu.
func (l *sessionLink) sendCloseLocked(code int, reason string) {
	l.mu.Lock()
	if l.writesOff {
		l.mu.Unlock()
		return
	}
	l.writesOff = true
	l.mu.Unlock()
	_ = l.conn.SetWriteDeadline(time.Now().Add(userWriteWait))
	_ = l.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason))
}

func (l *sessionLink) userWritesOff() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.writesOff
}

func (l *sessionLink) stopUserWrites() {
	l.mu.Lock()
	l.writesOff = true
	l.mu.Unlock()
}

// writeTunnelFrame sends one masked client control frame into the tunnel. It is
// the only path for the link's own keepalive, pong and close frames, so they
// are serialized and metered exactly like the user's data.
func (l *sessionLink) writeTunnelFrame(op byte, payload []byte) {
	l.mu.Lock()
	tunnel := l.tunnel
	l.mu.Unlock()
	if tunnel == nil {
		return
	}
	_, _ = tunnel.Write(hub.MaskClientFrame(op, payload))
}

// closeUpstream tells the provider that the user's side ended. A close frame
// received from the user is echoed with its own code and reason; a dropped
// socket becomes "going away". Codes reserved for local use (1005 no-status,
// 1006 abnormal) are never put on the wire, as RFC 6455 requires.
func (l *sessionLink) closeUpstream(err error) {
	code := uint16(websocket.CloseGoingAway)
	reason := "user connection lost"
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		code, reason = uint16(ce.Code), ce.Text
		switch {
		case code < 1000, code == 1004, code == 1005, code == 1006, code == 1015:
			code, reason = websocket.CloseGoingAway, "user connection lost"
		}
	}
	l.writeTunnelFrame(hub.WSOpClose, hub.ClosePayload(code, reason))
}

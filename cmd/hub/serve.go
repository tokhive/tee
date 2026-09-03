package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

// serveConfig is the routing the resident service hands to the scheduler: the
// upstream it asks the TEE to reach, per provider.
type serveConfig struct {
	Addr  string // where the Hub listens for its users
	Host  string // the AI service host:port (must be in every provider policy)
	Query string // extra upstream query (fault injection, for the harness)
	Max   uint64 // MaxResponseBytes cap passed to the TEE
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
	agentGatePath = "/v1/agent"
	teeRelayPath  = "/v1/relay"
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
	log.Printf("hub user-facing API listening on http://%s%v (sessions at %s)",
		cfg.Addr, routePaths(), sessionPath)
	log.Printf("hub reverse-tunnel endpoints: agent gate %s, tee relay %s", agentGatePath, teeRelayPath)
	log.Fatal(http.ListenAndServe(cfg.Addr, mux))
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
		writeJSONError(w, http.StatusBadRequest, "read body")
		return
	}
	var req struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Model == "" {
		writeJSONError(w, http.StatusBadRequest, "model is required")
		return
	}

	// Tenant resolution is the v1 placeholder: the user API key is not yet a
	// real auth system, so the caller identifies itself with a header.
	tenant := r.Header.Get("X-TokenHive-Key")
	if tenant == "" {
		tenant = "tenant-api"
	}

	flusher, _ := w.(http.Flusher)

	// The 200 + SSE headers are committed on the first relayed byte, not
	// before dispatch. A dispatch that fails before anything was relayed
	// (unknown model, quota, no serving provider) can therefore return a
	// proper JSON error with a meaningful status — an SSE error frame under a
	// 200 would leave SDKs guessing.
	var started bool
	start := func() {
		if started {
			return
		}
		started = true
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
	}

	var chunks int
	outcome, err := c.h.ExecuteForModel(r.Context(), tenant, req.Model, body,
		func(provider string) (jobs.Spec, error) {
			return buildSpec(provider, c.cfg.Host, c.route.Path, c.cfg.Query, body, c.cfg.Max)
		},
		func(chunk []byte) error {
			// The chunk is already the upstream's SSE bytes — mockprovider
			// frames `data: {…}` and the data path relays raw body bytes, so
			// re-wrapping here would emit `data: data: {…}` and break every
			// OpenAI SDK. The Hub's only job is byte-pass-through.
			start()
			if _, werr := w.Write(chunk); werr != nil {
				return werr
			}
			chunks++
			if flusher != nil {
				flusher.Flush()
			}
			return nil
		})

	if err != nil {
		if !started {
			writeJSONError(w, apiErrorStatus(err), err.Error())
			log.Printf("api model=%q path=%s tenant=%q err=%v", req.Model, c.route.Path, tenant, err)
			return
		}
		// Streaming had already begun: the status is committed, so the failure
		// is reported as an SSE error frame instead.
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", sseError(err))
	}
	if c.route.Done {
		// OpenAI-compatible chat streams terminate with an explicit done marker,
		// which the mock upstream does not emit. Appended after an error frame
		// too, so a client that started reading a stream is never left waiting
		// for a terminator that cannot come. An upstream that completed with an
		// empty body still needs the marker, hence the start() here.
		start()
		fmt.Fprint(w, "data: [DONE]\n\n")
	}
	if started && flusher != nil {
		flusher.Flush()
	}

	log.Printf("api model=%q path=%s tenant=%q provider=%q chunks=%d charged=%.2f commission=%.2f buyer=%.2f err=%v",
		req.Model, c.route.Path, tenant, outcome.Receipt.Receipt.Provider, chunks,
		float64(outcome.Charged)/microsPerUnit, float64(outcome.Commission)/microsPerUnit,
		float64(outcome.Buyer)/microsPerUnit, err)
}

// apiErrorStatus maps a dispatch failure to an HTTP status. A provider that
// simply cannot serve the model is a 404; quota exhaustion is a 429; anything
// else is a 502 upstream failure.
func apiErrorStatus(err error) int {
	switch {
	case errors.Is(err, hub.ErrNoProviderForModel), errors.Is(err, hub.ErrUnknownProvider):
		return http.StatusNotFound
	case errors.Is(err, hub.ErrQuotaExceeded):
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
const sessionPath = "/v1/session"

// sessionUpgrader upgrades the user's HTTP request to a WebSocket. Origin is
// unrestricted — the consumer is an API key holder, not a browser, so there is
// no origin header to police; the trust gate is the tenant header, exactly like
// the request routes.
var sessionUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(*http.Request) bool { return true },
}

// sessionHandler serves the streaming-session endpoint. It is the session
// counterpart of userHandler: read the model out of the first frame, let the
// scheduler pick the provider, relay the bytes, settle. The user's frames travel
// byte-for-byte; only the model field of the first frame is ever examined.
type sessionHandler struct {
	h   *hub.Hub
	cfg serveConfig
}

func (c *sessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := sessionUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	// Bound every user frame the relay reads (first frame and the uplink stream)
	// so a hostile client cannot blow the Hub's memory with an oversized message.
	conn.SetReadLimit(16 << 20)

	// The first frame is read here so the model can drive provider selection,
	// then handed back to the link, which replays it to the provider — reading
	// it costs the provider nothing and the bytes still travel unchanged.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, first, err := conn.ReadMessage()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	var req struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(first, &req); err != nil || req.Model == "" {
		return
	}

	tenant := r.Header.Get("X-TokenHive-Key")
	if tenant == "" {
		tenant = "tenant-api"
	}

	outcome, err := c.h.RunRealtime(r.Context(), tenant, req.Model, c.buildSession, &sessionLink{conn: conn, first: first})
	log.Printf("session model=%q tenant=%q provider=%q uplink=%d downlink=%d charged=%.2f commission=%.2f buyer=%.2f err=%v",
		req.Model, tenant, outcome.Provider, outcome.UplinkBytes, outcome.DownlinkBytes,
		float64(outcome.Charged)/microsPerUnit, float64(outcome.Commission)/microsPerUnit,
		float64(outcome.Buyer)/microsPerUnit, err)
}

// buildSession frames the session spec for a provider. Identical across providers
// except the provider name, exactly as buildSpec frames request specs.
func (c *sessionHandler) buildSession(provider string) (jobs.Spec, error) {
	jobID := make([]byte, jobs.JobIDLength)
	if _, err := rand.Read(jobID); err != nil {
		return jobs.Spec{}, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return jobs.Spec{}, err
	}
	return jobs.Spec{
		Version:          jobs.VersionV1,
		JobID:            jobID,
		Provider:         provider,
		Method:           "GET",
		Host:             c.cfg.Host,
		Path:             "/v1/realtime",
		Query:            c.cfg.Query,
		Headers:          map[string]string{},
		BodyHash:         hashBodyBytes(nil),
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
//     handed to the tunnel.
//   - Downlink: the tunnel yields the provider's raw server frames (possibly
//     split or bundled across tunnel messages), so Write decodes the frame stream
//     and re-emits each data frame's payload to the user as a fresh message.
//
// Like the TEE tunnel it is a full-duplex pipe: the Hub relays the two directions
// on separate goroutines, so the user socket is locked per direction and never
// across a blocking read (which would deadlock the session).
type sessionLink struct {
	conn *websocket.Conn

	readMu  sync.Mutex // serializes the uplink reader (one reader only)
	writeMu sync.Mutex // serializes the downlink writer (one writer only)

	// mu guards buf/readErr; the wire I/O happens after releasing it.
	mu      sync.Mutex
	first   []byte
	buf     []byte
	readErr error
	lastOp  int

	// down frames the incoming provider (server) frame stream. Only the downlink
	// writer touches it, so it is guarded by writeMu.
	down *hub.WsFrameDecoder
}

// Read returns the next provider-bound chunk: a legal masked client frame built
// from the user's message (or the replayed first frame). The bytes are exactly
// what the provider's own parser must accept.
func (l *sessionLink) Read(p []byte) (int, error) {
	l.readMu.Lock()
	defer l.readMu.Unlock()
	l.mu.Lock()
	// Pull one raw payload out of first/buf, then frame it below.
	var payload []byte
	if len(l.first) > 0 {
		payload = l.first
		l.first = nil
	} else {
		for len(l.buf) == 0 {
			if l.readErr != nil {
				err := l.readErr
				l.mu.Unlock()
				return 0, err
			}
			l.mu.Unlock()

			mt, msg, werr := l.conn.ReadMessage()
			l.mu.Lock()
			if werr != nil {
				l.readErr = werr
				l.mu.Unlock()
				return 0, werr
			}
			l.buf = msg
			l.lastOp = mt
		}
		payload = l.buf
		l.buf = nil
	}
	op := l.lastOp
	if op != websocket.BinaryMessage {
		op = websocket.TextMessage
	}
	frame := hub.MaskClientFrame(frameOpcode(op), payload)
	n := copy(p, frame)
	l.mu.Unlock()
	// Frame is at most payload length + 10 and p is at least the caller's 32 KiB
	// buffer, so a single user message always fits in one handed chunk. Assert
	// against a future buffer shrink rather than silently returning a partial.
	if n < len(frame) {
		return 0, io.ErrShortBuffer
	}
	return n, nil
}

func frameOpcode(mt int) byte {
	if mt == websocket.BinaryMessage {
		return hub.WSOpBinary
	}
	return hub.WSOpText
}

// Write consumes a tunnel downlink chunk (raw provider frames), decodes it, and
// re-emits each data frame's payload to the user as a fresh WebSocket message.
// It returns len(p) because every byte fed in is accounted for; a close frame
// (or a broken user socket) stops forwarding.
func (l *sessionLink) Write(p []byte) (int, error) {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	if l.down == nil {
		l.down = hub.NewWsFrameDecoder()
	}
	for _, f := range l.down.Feed(p) {
		if f.Terminal {
			break
		}
		if f.Opcode != hub.WSOpText && f.Opcode != hub.WSOpBinary {
			continue // control frames are not user data
		}
		msgType := websocket.TextMessage
		if f.Opcode == hub.WSOpBinary {
			msgType = websocket.BinaryMessage
		}
		if err := l.conn.WriteMessage(msgType, f.Data); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

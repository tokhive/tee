package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

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
	log.Printf("hub user-facing API listening on http://%s%v", cfg.Addr, routePaths())
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
		http.Error(w, `{"error":{"message":"read body"}}`, http.StatusBadRequest)
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

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, _ := w.(http.Flusher)
	w.WriteHeader(http.StatusOK)

	var chunks int
	outcome, err := c.h.ExecuteForModel(r.Context(), tenant, req.Model, body,
		func(provider string) (jobs.Spec, error) {
			return buildSpec(provider, c.cfg.Host, c.route.Path, req.Model, c.cfg.Query, body, c.cfg.Max, tenant)
		},
		func(chunk []byte) error {
			// The chunk is already the upstream's SSE bytes — mockprovider
			// frames `data: {…}` and the data path relays raw body bytes, so
			// re-wrapping here would emit `data: data: {…}` and break every
			// OpenAI SDK. The Hub's only job is byte-pass-through.
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
		// OpenAI-compatible APIs report upstream failures as an SSE error frame.
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", sseError(err))
	}
	if c.route.Done {
		// OpenAI-compatible chat streams terminate with an explicit done marker,
		// which the mock upstream does not emit. Appended after an error frame
		// too, so a client that started reading a stream is never left waiting
		// for a terminator that cannot come.
		fmt.Fprint(w, "data: [DONE]\n\n")
	}
	if flusher != nil {
		flusher.Flush()
	}

	log.Printf("api model=%q path=%s tenant=%q provider=%q chunks=%d charged=%.2f commission=%.2f buyer=%.2f err=%v",
		req.Model, c.route.Path, tenant, outcome.Receipt.Receipt.Provider, chunks,
		float64(outcome.Charged)/microsPerUnit, float64(outcome.Commission)/microsPerUnit,
		float64(outcome.Buyer)/microsPerUnit, err)
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

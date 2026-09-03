package main

import (
	"encoding/json"
	"errors"
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
			return buildSpec(provider, c.cfg.Host, c.route.Path, req.Model, c.cfg.Query, body, c.cfg.Max, tenant)
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

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
	Path  string // the upstream path
	Query string // extra upstream query (fault injection, for the harness)
	Max   uint64 // MaxResponseBytes cap passed to the TEE
}

// runServe exposes the Hub as a resident OpenAI-compatible HTTP service. It
// blocks until the server stops.
//
// Unlike the one-shot CLI (which pins a provider), this is the product shape:
// a user submits a chat request and the Hub decides which provider serves it,
// cheapest first, re-emitting the provider's SSE stream to the user.
func runServe(h *hub.Hub, cfg serveConfig) {
	mux := http.NewServeMux()
	mux.Handle("/v1/chat/completions", &chatHandler{h: h, cfg: cfg})

	log.Printf("hub user-facing API listening on http://%s/v1/chat/completions", cfg.Addr)
	log.Fatal(http.ListenAndServe(cfg.Addr, mux))
}

// chatHandler implements POST /v1/chat/completions with SSE streaming. The
// request body is forwarded byte-for-byte to the TEE (bound by BodyHash), but
// the model field is read out first because it drives provider selection.
type chatHandler struct {
	h   *hub.Hub
	cfg serveConfig
}

func (c *chatHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
			return buildSpec(provider, c.cfg.Host, req.Model, c.cfg.Query, body, c.cfg.Max, tenant)
		},
		func(chunk []byte) error {
			if _, werr := fmt.Fprintf(w, "data: %s\n\n", chunk); werr != nil {
				return werr
			}
			chunks++
			if flusher != nil {
				flusher.Flush()
			}
			return nil
		})

	if err != nil {
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", strings.ReplaceAll(err.Error(), "\n", " "))
	}
	// OpenAI-compatible streams terminate with an explicit done marker, which
	// the upstream does not emit.
	fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}

	log.Printf("chat model=%q tenant=%q provider=%q chunks=%d charged=%.2f commission=%.2f buyer=%.2f err=%v",
		req.Model, tenant, outcome.Receipt.Receipt.Provider, chunks,
		float64(outcome.Charged)/microsPerUnit, float64(outcome.Commission)/microsPerUnit,
		float64(outcome.Buyer)/microsPerUnit, err)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"error":{"message":%q}}`, msg)
}

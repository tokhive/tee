package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// These tests exercise the user-facing routes (chat completions, Anthropic
// messages, OpenAI Responses) against a scripted TEE: no network, no real
// credential. They lock the Hub's contract on each route: the body's model
// field drives lowest-price provider selection, upstream bytes are relayed
// verbatim (never double-wrapped in another data: frame), and the OpenAI chat
// route alone appends the [DONE] terminator — the other two formats carry
// their own end markers.

// newServeTestHub builds a Hub whose scripted TEE answers every request with
// the supplied upstream SSE bytes (the fixed frames mockprovider serves).
func newServeTestHub(t *testing.T, upstream []byte) *hub.Hub {
	t.Helper()
	return newServeTestHubStatus(t, upstream, 200, nil)
}

// newServeTestHubStatus is newServeTestHub with control over the upstream
// status and the TEE's Reply error, so a test can exercise the pre-dispatch
// error path (every provider refuses) and the upstream-error passthrough.
func newServeTestHubStatus(t *testing.T, upstream []byte, status int, fail error) *hub.Hub {
	t.Helper()

	// The sim fixtures (seller rate table for openai-sim and cheap-sim, plus
	// the per-provider whitelist policies) are generated into a private temp
	// dir so the test never touches the working tree's .sim. Credentials are
	// deliberately absent: they arrive at runtime through agent registration,
	// which these route tests do not exercise (they use a scripted TEE).
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)
	if err := shared.EnsureDefaults(); err != nil {
		t.Fatalf("ensure defaults: %v", err)
	}
	rates, err := shared.LoadRates()
	if err != nil {
		t.Fatalf("load rates: %v", err)
	}

	stream := [][]byte{upstream}
	ctype := "text/event-stream"
	if status != 200 {
		ctype = "application/json"
	}
	fake := &hub.ScriptedTEE{Reply: func(call int, spec jobs.Spec) (hub.Result, error) {
		if fail != nil {
			return hub.Result{}, fail
		}
		r := hub.ScriptReceipt(stream, proof.Receipt{
			Provider:      spec.Provider,
			StatusCode:    uint32(status),
			Completion:    proof.CompletionComplete,
			ChunkCount:    1,
			ResponseBytes: uint64(len(upstream)),
			ProviderSeq:   uint64(call),
		})
		return hub.Result{
			Status:  uint32(status),
			Headers: map[string][]string{"content-type": {ctype}},
			Chunks:  stream,
			Receipt: proof.SignedReceipt{Receipt: r},
		}, nil
	}}

	h, err := hub.New(hub.Config{
		TEE:        fake,
		Rates:      rates,
		Store:      hub.NewReceiptStore(t.TempDir()),
		Verify:     func(proof.SignedReceipt) error { return nil },
		Commission: 0,
	})
	if err != nil {
		t.Fatalf("build hub: %v", err)
	}
	return h
}

// newServeTestHubReply is kept for the pre-dispatch failure test: a TEE whose
// Reply always fails.
func newServeTestHubReply(t *testing.T, upstream []byte, fail error) *hub.Hub {
	t.Helper()
	return newServeTestHubStatus(t, upstream, 200, fail)
}

// postBody hits one user-facing route with a JSON body and returns the raw
// response bytes.
func postBody(t *testing.T, route userRoute, body string) (string, string) {
	t.Helper()
	return serveRequest(t, newServeTestHub(t, []byte("data: {\"id\":\"chatcmpl-sim1\"}\n\n")), route, body)
}

// serveRequest runs one route against a ready hub.
func serveRequest(t *testing.T, h *hub.Hub, route userRoute, body string) (string, string) {
	t.Helper()

	// Fixture policy hosts point at 127.0.0.1:18080, which is also what the
	// route config passes upstream. cheap-sim (0.30) must win over openai-sim
	// (1.00) for every model, exactly as in harness scenario 15.
	cfg := serveConfig{Host: "127.0.0.1:18080", Query: "", Max: 1 << 20}
	handler := &userHandler{h: h, cfg: cfg, route: route}

	req := httptest.NewRequest(http.MethodPost, route.Path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TokenHive-Key", "tenant-test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Body.String(), rec.Header().Get("Content-Type")
}

func TestChatRouteAppendsDoneAndRelaysVerbatim(t *testing.T) {
	body, _ := postBody(t, userRoutes[0], `{"model":"sim-mock-0.5b","messages":[{"role":"user","content":"hi"}]}`)
	if !strings.Contains(body, "data: {\"id\":\"chatcmpl-sim1\"}") {
		t.Fatalf("upstream bytes missing from response: %q", body)
	}
	if !strings.HasSuffix(body, "\ndata: [DONE]\n\n") {
		t.Fatalf("chat stream must terminate with [DONE], got: %q", body)
	}
	if strings.Contains(body, "data: data:") {
		t.Fatalf("upstream bytes were double-wrapped in another data: frame: %q", body)
	}
}

func TestMessagesRouteRelaysAnthropicBytesVerbatim(t *testing.T) {
	// The upstream (mockprovider) serves Anthropic framing: event: message_start
	// ... event: message_stop. The Hub must not add [DONE] — message_stop is the
	// client's end marker.
	route := userRoutes[1]
	body, _ := postBody(t, route, `{"model":"sim-claude-haiku","max_tokens":64,"messages":[{"role":"user","content":"hi"}],"stream":true}`)
	if !strings.Contains(body, "chatcmpl-sim1") {
		t.Fatalf("upstream bytes missing from response: %q", body)
	}
	if strings.Contains(body, "[DONE]") {
		t.Fatalf("Anthropic route must not append [DONE]: %q", body)
	}
}

func TestResponsesRouteRelaysResponsesBytesVerbatim(t *testing.T) {
	// OpenAI Responses framing ends with a response.completed event of its own.
	route := userRoutes[2]
	body, _ := postBody(t, route, `{"model":"sim-mock-0.5b","input":"hi","stream":true}`)
	if !strings.Contains(body, "chatcmpl-sim1") {
		t.Fatalf("upstream bytes missing from response: %q", body)
	}
	if strings.Contains(body, "[DONE]") {
		t.Fatalf("Responses route must not append [DONE]: %q", body)
	}
}

func TestUserRoutesServeStreamingContentType(t *testing.T) {
	for _, route := range userRoutes {
		body, ctype := postBody(t, route, `{"model":"sim-mock-0.5b"}`)
		if !strings.Contains(ctype, "text/event-stream") {
			t.Errorf("%s content-type = %q, want text/event-stream", route.Path, ctype)
		}
		if body == "" {
			t.Errorf("%s returned an empty stream", route.Path)
		}
	}
}

// TestUpstreamErrorStatusIsPassedThrough locks the fix this protocol change
// exists for: when the upstream answers 401, the buyer sees a 401 with the
// upstream's error body — not a 200 with an SSE stream. The upstream's own
// body is the complete error, so no [DONE] marker is appended to it.
func TestUpstreamErrorStatusIsPassedThrough(t *testing.T) {
	route := userRoutes[0]
	h := newServeTestHubStatus(t,
		[]byte(`{"error":{"message":"invalid api key"}}`), 401, nil)
	status, body, ctype := serveStatus(t, h, route, `{"model":"sim-mock-0.5b"}`)
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
	if !strings.Contains(ctype, "application/json") {
		t.Errorf("content-type = %q, want the upstream's application/json", ctype)
	}
	if !strings.Contains(body, `{"error":{"message":"invalid api key"}}`) {
		t.Errorf("upstream error body missing: %q", body)
	}
	if strings.Contains(body, "[DONE]") {
		t.Errorf("error body must not be spliced with a stream terminator: %q", body)
	}
	if strings.Contains(body, "event: error") {
		t.Errorf("hub error frame must not be spliced into a non-2xx error body: %q", body)
	}
}

// TestUpstreamErrorStatusAlsoPassesThroughRateLimit covers the 429 shape: the
// upstream's Retry-After hint must reach the buyer alongside the status.
func TestUpstreamErrorStatusAlsoPassesThroughRateLimit(t *testing.T) {
	route := userRoutes[0]
	// A 429 receipt is not billable, so the scheduler would fall back to the
	// next provider; with both providers scripted to 429, the last attempt is
	// returned and its status is what the buyer sees.
	h := newServeTestHubStatus(t,
		[]byte(`{"error":{"message":"rate limit exceeded"}}`), 429, nil)
	status, _, _ := serveStatus(t, h, route, `{"model":"sim-mock-0.5b"}`)
	if status != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", status)
	}
}

// serveStatus runs one route and returns the recorded status, body, and
// content type.
func serveStatus(t *testing.T, h *hub.Hub, route userRoute, body string) (int, string, string) {
	t.Helper()
	cfg := serveConfig{Host: "127.0.0.1:18080", Query: "", Max: 1 << 20}
	handler := &userHandler{h: h, cfg: cfg, route: route}

	req := httptest.NewRequest(http.MethodPost, route.Path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TokenHive-Key", "tenant-test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), rec.Header().Get("Content-Type")
}

// TestPreDispatchFailureIsAJSONError locks the deferred-header behaviour: a
// dispatch that fails before any byte is relayed (here: every provider
// refuses) must return a proper JSON error with a non-2xx status, not an SSE
// error frame smuggled under a 200.
func TestPreDispatchFailureIsAJSONError(t *testing.T) {
	route := userRoutes[0]
	failing := newServeTestHubReply(t, []byte("data: {\"id\":\"chatcmpl-sim1\"}\n\n"), errors.New("tee refused"))
	body, ctype := serveRequest(t, failing, route, `{"model":"sim-mock-0.5b"}`)
	if strings.Contains(ctype, "text/event-stream") {
		t.Fatalf("error response used SSE content-type %q; want application/json", ctype)
	}
	if !strings.Contains(body, "error") {
		t.Fatalf("error body is not JSON: %q", body)
	}
}

// TestModelsEndpointShape pins the /v1/models wire contract at the serve
// layer: JSON with a "models" array, empty (not null) when this Hub has no
// agent gate and therefore nothing declared. Search and directory semantics
// live in the hub package tests; here we only lock the envelope.
func TestModelsEndpointShape(t *testing.T) {
	h := newServeTestHub(t, []byte("x"))
	handler := modelsHandler(h)

	req := httptest.NewRequest(http.MethodGet, modelsPath, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ctype := rec.Header().Get("Content-Type")
	if !strings.Contains(ctype, "application/json") {
		t.Fatalf("content-type = %q, want application/json", ctype)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"models":[]}` {
		t.Fatalf("empty directory body = %q, want {\"models\":[]}", body)
	}

	// A query parameter is accepted and still yields an empty (filtered) list.
	req = httptest.NewRequest(http.MethodGet, modelsPath+"?q=deepseek", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if body := strings.TrimSpace(rec.Body.String()); body != `{"models":[]}` {
		t.Fatalf("filtered empty directory body = %q, want {\"models\":[]}", body)
	}
}

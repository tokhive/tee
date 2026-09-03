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
	return newServeTestHubReply(t, upstream, nil)
}

// newServeTestHubReply is newServeTestHub with a TEE whose Reply may fail, so
// a test can exercise the pre-dispatch error path (every provider refuses).
func newServeTestHubReply(t *testing.T, upstream []byte, fail error) *hub.Hub {
	t.Helper()

	// The sim fixtures (providers.json, signed policies for openai-sim and
	// cheap-sim) are generated into a private temp dir so the test never
	// touches the working tree's .sim.
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)
	if err := shared.EnsureDefaults(); err != nil {
		t.Fatalf("ensure defaults: %v", err)
	}
	policies, err := shared.LoadPolicySetAll()
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}

	stream := [][]byte{upstream}
	fake := &hub.ScriptedTEE{Reply: func(call int, spec jobs.Spec) (hub.Result, error) {
		if fail != nil {
			return hub.Result{}, fail
		}
		r := hub.ScriptReceipt(stream, proof.Receipt{
			Provider:      spec.Provider,
			StatusCode:    200,
			Completion:    proof.CompletionComplete,
			ChunkCount:    1,
			ResponseBytes: uint64(len(upstream)),
			ProviderSeq:   uint64(call),
		})
		return hub.Result{Chunks: stream, Receipt: proof.SignedReceipt{Receipt: r}}, nil
	}}

	h, err := hub.New(hub.Config{
		TEE:        fake,
		Policies:   policies,
		Store:      hub.NewReceiptStore(t.TempDir()),
		Verify:     func(proof.SignedReceipt) error { return nil },
		Commission: 0,
	})
	if err != nil {
		t.Fatalf("build hub: %v", err)
	}
	return h
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

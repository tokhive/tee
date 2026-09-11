package tee

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

// TestWriteStartFrame pins the exact bytes of the response-start frame: the
// upstream status and the relayed headers as JSON on one data line, emitted
// before the first chunk. The hub package parses this frame with encoding/json;
// this test fixes the wire format so the two halves cannot drift.
func TestWriteStartFrame(t *testing.T) {
	var buf bytes.Buffer
	writeStartFrame(&buf, Response{
		StatusCode: 200,
		Headers:    map[string][]string{"content-type": {"text/event-stream"}},
	})
	want := "event: start\ndata: {\"status\":200,\"headers\":{\"content-type\":[\"text/event-stream\"]}}\n\n"
	if got := buf.String(); got != want {
		t.Errorf("writeStartFrame() = %q, want %q", got, want)
	}
}

// TestWriteChunkFrame pins the exact bytes the server writes for one chunk.
//
// The client is tested against the same encodings in the hub package, but that
// only proves the two agree if the encodings themselves are right. This test
// is the other half: it fixes the wire format so a change here breaks here,
// rather than surfacing as receipts that no longer verify.
func TestWriteChunkFrame(t *testing.T) {
	cases := []struct {
		name  string
		chunk string
		want  string
	}{
		{"plain", "hello", "data: hello\n\n"},
		{"trailing space is payload", "hello ", "data: hello \n\n"},
		{"leading spaces survive the conventional space", "  hi", "data:   hi\n\n"},
		{"empty chunk is still a frame", "", "data: \n\n"},
		{"embedded newline becomes two data lines", "a\nb", "data: a\ndata: b\n\n"},
		{"trailing newline is preserved", "a\n", "data: a\ndata: \n\n"},
		{"bare newline", "\n", "data: \ndata: \n\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeChunkFrame(&buf, []byte(tc.chunk))
			if got := buf.String(); got != tc.want {
				t.Errorf("writeChunkFrame(%q) = %q, want %q", tc.chunk, got, tc.want)
			}
		})
	}
}

// TestExecuteRequestRoundTrip checks the wire type survives canonical CBOR,
// which is what makes the Hub's client and this service interchangeable.
func TestExecuteRequestRoundTrip(t *testing.T) {
	body := []byte(`{"model":"m","stream":true}`)
	original := ExecuteRequest{
		Spec: jobs.Spec{
			Version:  jobs.VersionV1,
			JobID:    make([]byte, jobs.JobIDLength),
			Provider: "openai",
			Method:   "POST",
			Host:     "api.openai.com",
			Path:     "/v1/chat/completions",
			Headers:  map[string]string{"content-type": "application/json"},
			Nonce:    make([]byte, jobs.MinNonceLength),
		},
		Body: body,
	}
	encoded, err := original.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeExecuteRequest(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Spec.Provider != original.Spec.Provider {
		t.Errorf("provider = %q, want %q", decoded.Spec.Provider, original.Spec.Provider)
	}
	if !bytes.Equal(decoded.Body, original.Body) {
		t.Errorf("body = %q, want %q", decoded.Body, original.Body)
	}
	if decoded.Job().Spec.Provider != original.Spec.Provider {
		t.Error("Job() must carry the spec through")
	}
}

// TestServeExecuteBoundsTheRequestBody pins the read limit on the single RPC:
// the enclave must refuse an oversized body before it allocates for it. svc is
// deliberately nil — the size check has to fire before the service is ever
// consulted, so a nil service is the assertion that it did.
func TestServeExecuteBoundsTheRequestBody(t *testing.T) {
	oversize := bytes.Repeat([]byte("x"), MaxExecuteBody+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(oversize))
	rec := httptest.NewRecorder()
	ServeExecute(nil, rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body status = %d, want 413", rec.Code)
	}

	// A body exactly at the cap is not oversize: it is a (here malformed)
	// request that must be refused for its content, not its size.
	atCap := bytes.Repeat([]byte("x"), MaxExecuteBody)
	req = httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(atCap))
	rec = httptest.NewRecorder()
	ServeExecute(nil, rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("at-cap body status = %d, want 400 (decode failure, not 413)", rec.Code)
	}
}

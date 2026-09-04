package tee

import (
	"bytes"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

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

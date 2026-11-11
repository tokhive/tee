package tee

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/tokhive/tee/internal/canonical"

	"github.com/tokhive/tee/jobs"
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

// TestServeExecuteClearsTheBodyReadDeadline pins both halves of the bound on
// reading the request body. Once the body is in hand the deadline must go: it
// sits on the same socket the SSE answer streams over, and net/http keeps a
// background read armed on that socket for the whole request, so a deadline
// left in place expires under a long execution, fails that background read,
// and makes the server cancel the request context — cutting a healthy job
// mid-stream for no reason but its duration. On the oversize path the opposite
// holds: bytes are still arriving and net/http drains up to 256 KiB of them
// after the handler returns, so the deadline must stay on or a peer dribbling
// an oversized chunked body pins the connection.
func TestServeExecuteClearsTheBodyReadDeadline(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  []byte
		clear bool
	}{
		{"body_in_hand", []byte("not-canonical-cbor"), true},
		{"oversize_body", bytes.Repeat([]byte("x"), MaxExecuteBody+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(tc.body))
			ServeExecute(nil, rec, req)

			if len(rec.deadlines) == 0 || rec.deadlines[0].IsZero() {
				t.Fatal("the body read was not bounded by a deadline")
			}
			cleared := len(rec.deadlines) == 2 && rec.deadlines[1].IsZero()
			if tc.clear && !cleared {
				t.Fatalf("read deadline left set (%v); it would cut any execution that outlives it", rec.deadlines)
			}
			if !tc.clear && cleared {
				t.Fatal("read deadline cleared with the body still arriving; the post-handler drain would be unbounded")
			}
			if len(rec.deadlines) > 2 {
				t.Fatalf("unexpected deadline churn: %v", rec.deadlines)
			}
		})
	}
}

// deadlineRecorder is an httptest.ResponseRecorder that also satisfies the
// SetReadDeadline half of http.ResponseController, recording what the handler
// asks the socket for.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

// serveExecuteFrames drives one request through the handler and returns the
// frames it wrote, in order. The failure frame is the one piece of the stream
// with no receipt to keep it honest, so its position is worth pinning: the Hub
// settles against the receipt, and a diagnosis that arrives after it would be
// read too late to describe the exchange it belongs to.
func serveExecuteFrames(t *testing.T, env *testEnv, payload []byte) []SSEEvent {
	t.Helper()
	spec := env.spec(t, payload)
	body, err := ExecuteRequest{Spec: spec, Body: payload}.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode execute request: %v", err)
	}
	rec := httptest.NewRecorder()
	ServeExecute(env.service, rec, httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("execute status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var frames []SSEEvent
	stream := NewSSEStream(rec.Body)
	for {
		frame, err := stream.Next()
		if err != nil {
			return frames
		}
		frames = append(frames, frame)
	}
}

// TestServeExecuteSaysWhyTheExchangeFailed pins the whole path a diagnosis
// takes: a transport error the TEE's own vocabulary can place, classified by
// the service, emitted as a frame ahead of the receipt that attests the same
// exchange. Before this frame existed the Hub saw CompletionFailed and a zero
// status, which is what a provider that never answered looks like too.
func TestServeExecuteSaysWhyTheExchangeFailed(t *testing.T) {
	env := newTestEnv(t)
	env.transport.statusCode = 0
	env.transport.chunks = nil
	env.transport.failAfter = 0
	env.transport.err = &StageError{Stage: StageTTFB, Cold: true, Err: io.EOF}

	frames := serveExecuteFrames(t, env, []byte(`{"model":"m"}`))

	var failureAt, receiptAt = -1, -1
	for i, frame := range frames {
		switch frame.Type {
		case EventFailure:
			failureAt = i
		case EventReceipt:
			receiptAt = i
		}
	}
	if failureAt < 0 {
		t.Fatal("no failure frame: the Hub has nothing to tell the provider from")
	}
	if receiptAt < 0 {
		t.Fatal("no receipt frame")
	}
	if failureAt > receiptAt {
		t.Fatalf("failure frame written after the receipt (frames %d and %d); the Hub settles before it could read the diagnosis", failureAt, receiptAt)
	}

	var failure Failure
	if err := json.Unmarshal([]byte(frames[failureAt].Data), &failure); err != nil {
		t.Fatalf("decode failure frame: %v", err)
	}
	if failure.Class != FailureUpstreamClosed || failure.Stage != StageTTFB || !failure.Cold {
		t.Errorf("failure = %+v, want upstream_closed at ttfb on a cold connection", failure)
	}
}

// TestServeExecuteSaysNothingExtraWhenTheExchangeCompleted pins the other half
// of the contract: silence means the exchange finished whole, so a Hub never
// has to tell "no diagnosis" from "a diagnosis it could not read".
func TestServeExecuteSaysNothingExtraWhenTheExchangeCompleted(t *testing.T) {
	env := newTestEnv(t)
	for _, frame := range serveExecuteFrames(t, env, []byte(`{"model":"m"}`)) {
		if frame.Type == EventFailure {
			t.Fatalf("a completed exchange emitted a failure frame: %q", frame.Data)
		}
	}
}

// TestInPlaceDecodeAgreesWithCanonical holds the fast path of
// DecodeExecuteRequest to the general one. The fast path may decline an input
// — the general decoder then decides — but whenever it accepts, the general
// decoder must accept too and produce the same request; and every canonical
// encoding must take the fast path, or the copies it exists to avoid come back
// unnoticed.
func TestInPlaceDecodeAgreesWithCanonical(t *testing.T) {
	spec := jobs.Spec{
		JobID:    bytes.Repeat([]byte{7}, 16),
		Provider: "p1",
		Method:   "POST",
		Host:     "api.example.com",
		Path:     "/v1/x",
		Headers:  map[string]string{"content-type": "application/json"},
	}
	bodies := [][]byte{
		nil, {}, []byte("x"),
		bytes.Repeat([]byte("a"), 23), bytes.Repeat([]byte("a"), 24),
		bytes.Repeat([]byte("a"), 255), bytes.Repeat([]byte("a"), 256),
		bytes.Repeat([]byte("a"), 65535), bytes.Repeat([]byte("a"), 65536),
	}
	for _, body := range bodies {
		encoded, err := (ExecuteRequest{Spec: spec, Body: body}).EncodeCanonical()
		if err != nil {
			t.Fatal(err)
		}
		fast, ok := decodeExecuteRequestInPlace(encoded)
		if !ok {
			t.Fatalf("canonical encoding with a %d-byte body missed the fast path", len(body))
		}
		var slow ExecuteRequest
		if err := canonical.Unmarshal(encoded, &slow); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(fast, slow) {
			t.Fatalf("fast and canonical decodes differ for a %d-byte body", len(body))
		}

		// Every single-byte corruption and every truncation: the fast path may
		// refuse, but it must never accept what the canonical decoder rejects,
		// nor read the same bytes as a different request.
		if len(encoded) > 4096 {
			continue
		}
		check := func(mutated []byte) {
			fast, ok := decodeExecuteRequestInPlace(mutated)
			if !ok {
				return
			}
			var slow ExecuteRequest
			if err := canonical.Unmarshal(mutated, &slow); err != nil {
				t.Fatalf("fast path accepted input the canonical decoder rejects: %v", err)
			}
			if !reflect.DeepEqual(fast, slow) {
				t.Fatal("fast path decoded a mutated input differently")
			}
		}
		for i := range encoded {
			for _, flip := range []byte{0x01, 0x20, 0x80, 0xff} {
				mutated := append([]byte(nil), encoded...)
				mutated[i] ^= flip
				check(mutated)
			}
			check(encoded[:i])
			check(append(append([]byte(nil), encoded...), encoded[i]))
		}
	}
}

// TestCanonicalByteStringRejectsLongForms pins the half of canonical form the
// in-place decode checks by hand: a length that fits a shorter header must use
// it, and an indefinite-length string is never canonical.
func TestCanonicalByteStringRejectsLongForms(t *testing.T) {
	for name, data := range map[string][]byte{
		"1-byte length under 24":    {0x58, 0x01, 'a'},
		"2-byte length under 256":   {0x59, 0x00, 0x01, 'a'},
		"4-byte length under 65536": {0x5a, 0x00, 0x00, 0x00, 0x01, 'a'},
		"8-byte length under 2^32":  {0x5b, 0, 0, 0, 0, 0, 0, 0, 1, 'a'},
		"indefinite":                {0x5f, 0x41, 'a', 0xff},
		"trailing byte":             {0x41, 'a', 'b'},
		"short":                     {0x42, 'a'},
		"text string":               {0x61, 'a'},
	} {
		if _, ok := canonicalByteString(data); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	if got, ok := canonicalByteString([]byte{0x41, 'a'}); !ok || string(got) != "a" {
		t.Errorf("shortest form refused: %q %v", got, ok)
	}
}

// TestReadBoundedHonoursTheCapNotTheDeclaredLength: the declared length sizes
// the buffer and nothing else, so a body longer than it announced is still read
// to the cap and still caught there.
func TestReadBoundedHonoursTheCapNotTheDeclaredLength(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 100)
	for _, declared := range []int64{-1, 0, 10, 100, 1 << 40} {
		got, err := readBounded(bytes.NewReader(body), declared, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 51 {
			t.Errorf("declared %d: read %d bytes, want cap+1 = 51", declared, len(got))
		}
		got, err = readBounded(bytes.NewReader(body), declared, 1000)
		if err != nil || !bytes.Equal(got, body) {
			t.Errorf("declared %d: body not read whole (%d bytes, %v)", declared, len(got), err)
		}
	}
}

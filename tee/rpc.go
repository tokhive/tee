package tee

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// The Hub↔TEE interface is a single RPC: POST /v1/execute carrying a canonical
// ExecuteRequest, answered by an SSE stream of response chunks terminated by a
// receipt frame. Everything else — pricing, quota, scheduling — lives on the
// Hub side of this seam.
const (
	// ExecuteContentType is the request content type of the single RPC.
	ExecuteContentType = "application/cbor"

	// EventReceipt names the final SSE frame, whose data is the base64 of a
	// canonical SignedReceipt.
	EventReceipt = "receipt"

	// EventError names the frame a refusal produces. A refusal has no receipt,
	// so a caller that treats "no receipt frame" and "error frame" as the same
	// case loses the reason; they are deliberately distinct.
	EventError = "error"
)

// ExecuteRequest is the body of POST /v1/execute: a canonical JobSpec plus the
// raw request bytes the TEE will send to the provider.
//
// The wire type lives beside the service that consumes it rather than beside
// the Hub that produces it, so that the client and the server are written
// against one definition and cannot drift apart.
type ExecuteRequest struct {
	Spec jobs.Spec `cbor:"1,keyasint"`
	Body []byte    `cbor:"2,keyasint"`
}

// EncodeCanonical returns the deterministic CBOR encoding of the request.
func (r ExecuteRequest) EncodeCanonical() ([]byte, error) { return canonical.Marshal(r) }

// DecodeExecuteRequest parses a canonical-CBOR ExecuteRequest.
func DecodeExecuteRequest(data []byte) (ExecuteRequest, error) {
	var r ExecuteRequest
	if err := canonical.Unmarshal(data, &r); err != nil {
		return ExecuteRequest{}, err
	}
	return r, nil
}

// Job converts the request into the execution input the Service takes.
func (r ExecuteRequest) Job() Job { return Job{Spec: r.Spec, Body: r.Body} }

// ServeExecute is the server half of the single RPC. It wraps the real
// Service: nothing here re-implements the TEE, it only adapts the execution
// result onto the wire.
//
// A refusal is reported as an EventError frame, so the caller learns why
// without a credential ever being touched.
func ServeExecute(svc *Service, w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	req, err := DecodeExecuteRequest(raw)
	if err != nil {
		http.Error(w, "decode request: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	onChunk := func(chunk []byte) error {
		writeChunkFrame(w, chunk)
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}

	res, err := svc.Execute(r.Context(), req.Job(), onChunk)
	if err != nil {
		writeEvent(w, flusher, EventError, err.Error())
		return
	}
	enc, err := res.Receipt.EncodeCanonical()
	if err != nil {
		writeEvent(w, flusher, EventError, "encode receipt: "+err.Error())
		return
	}
	writeEvent(w, flusher, EventReceipt, base64.StdEncoding.EncodeToString(enc))
}

// writeChunkFrame emits one response chunk as an SSE data event.
//
// The framing has to round-trip bytes exactly, because the receipt's stream
// hash covers the chunks the TEE wrote and the Hub checks it against the ones
// it read. Two details make that work:
//
//   - A chunk is written as one `data:` line per line it contains, since SSE
//     joins multi-line data with \n and a raw newline inside a chunk would
//     otherwise close the frame early and split one chunk into two.
//   - The conventional single space after `data:` is always emitted, and the
//     reader strips exactly one, so a chunk that itself begins with spaces
//     survives. Only leading whitespace is conventional; trailing whitespace is
//     payload and must not be trimmed, which is why this does not use a
//     general trim.
//
// A chunk is never skipped, including an empty one: StreamingHasher counts
// empty writes, so a dropped heartbeat would change both the chunk count and
// the hash, and every receipt for that job would fail to verify.
func writeChunkFrame(w io.Writer, chunk []byte) {
	for _, line := range bytes.Split(chunk, []byte("\n")) {
		fmt.Fprintf(w, "data: %s\n", line)
	}
	fmt.Fprint(w, "\n")
}

// writeEvent emits one SSE frame. Entries are flushed individually because the
// whole point of the stream is that the caller sees chunks as they arrive —
// a buffered stream would make TTFT unmeasurable and defeat the format.
func writeEvent(w http.ResponseWriter, flusher http.Flusher, event, data string) {
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	if flusher != nil {
		flusher.Flush()
	}
}

// DecodeReceiptFrame parses the data line of an EventReceipt frame.
func DecodeReceiptFrame(data string) (proof.SignedReceipt, error) {
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return proof.SignedReceipt{}, fmt.Errorf("decode receipt frame: %w", err)
	}
	var signed proof.SignedReceipt
	if err := canonical.Unmarshal(raw, &signed); err != nil {
		return proof.SignedReceipt{}, fmt.Errorf("parse receipt: %w", err)
	}
	return signed, nil
}

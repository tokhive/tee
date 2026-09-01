package hub

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// Errors returned by the TEE client.
var (
	// ErrNoReceipt means the stream ended without a receipt frame. The chunks
	// may still have been delivered, so this is not the same as a refusal: it
	// is a job that happened and left nothing to settle against.
	ErrNoReceipt = errors.New("tee stream ended without a receipt frame")
	// ErrTEERefused means the TEE answered with an error frame: it declined
	// the job before touching a credential.
	ErrTEERefused = errors.New("tee refused the job")
)

// Result is what one call to the TEE produced.
type Result struct {
	// Chunks are the response bytes, in order. They are what the receipt's
	// StreamHash commits to.
	Chunks [][]byte
	// Receipt is the signed proof. Verify it before relying on it.
	Receipt proof.SignedReceipt
}

// TEE is the entire Hub↔TEE seam: one method.
//
// The narrowness is the point. Every piece of Hub business — pricing, quota,
// ledger, scheduling — sits behind this interface, so all of it can be
// exercised against an in-memory stand-in without a TEE, a network, or a real
// credential.
type TEE interface {
	// Execute runs a job and reports the forwarded chunks and the receipt.
	// onChunk receives each response chunk as it arrives and may be nil.
	//
	// On error the Result is still returned when the TEE got far enough to
	// produce one: a job that failed mid-flight has something to prove, and
	// the Hub needs it to show it did not get what it was paying for.
	Execute(ctx context.Context, spec jobs.Spec, body []byte, onChunk func([]byte) error) (Result, error)
}

// HTTPTEE calls a TEE's /v1/execute over HTTP. It is the production
// implementation of TEE.
type HTTPTEE struct {
	// URL is the full endpoint, e.g. http://127.0.0.1:18090/v1/execute.
	URL string
	// Client is the HTTP client to use. Defaults to http.DefaultClient.
	Client *http.Client
}

// Execute implements TEE.
func (t *HTTPTEE) Execute(ctx context.Context, spec jobs.Spec, body []byte, onChunk func([]byte) error) (Result, error) {
	if t.URL == "" {
		return Result{}, errors.New("hub: TEE URL is empty")
	}
	enc, err := tee.ExecuteRequest{Spec: spec, Body: body}.EncodeCanonical()
	if err != nil {
		return Result{}, fmt.Errorf("encode execute request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(enc))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", tee.ExecuteContentType)

	client := t.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Result{}, fmt.Errorf("tee http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return readSSE(resp.Body, onChunk)
}

// readSSE parses the response stream, handing each chunk to onChunk and
// stopping at the receipt or error frame.
//
// Chunks are collected as well as forwarded because the Hub settles against
// them: it must be able to show the receipt attests exactly the bytes it
// delivered, which needs the bytes, not just the fact of delivery.
func readSSE(r io.Reader, onChunk func([]byte) error) (Result, error) {
	reader := bufio.NewReader(r)
	var (
		eventType string
		data      strings.Builder
		dataLines int
		chunks    [][]byte
		receipt   string
		teeErr    string
	)
	flush := func() {
		switch eventType {
		case "", "message":
			// Keyed on dataLines rather than on the accumulated length: an
			// empty chunk is a real chunk and must be kept, or the count and
			// the stream hash stop matching the receipt.
			if dataLines > 0 {
				payload := data.String()
				chunks = append(chunks, []byte(payload))
				if onChunk != nil {
					_ = onChunk([]byte(payload))
				}
			}
		case tee.EventReceipt:
			receipt = data.String()
		case tee.EventError:
			teeErr = data.String()
		}
		eventType = ""
		data.Reset()
		dataLines = 0
	}

	for {
		line, err := reader.ReadString('\n')
		trimmed := strings.TrimRight(line, "\r\n")
		switch {
		case trimmed == "":
			flush()
		case strings.HasPrefix(trimmed, "event:"):
			eventType = strings.TrimSpace(strings.TrimPrefix(trimmed, "event:"))
		case strings.HasPrefix(trimmed, "data:"):
			// SSE joins consecutive data lines with \n and removes exactly one
			// leading space. Nothing else is touched: the chunk is payload the
			// receipt hashes, so trimming it would silently corrupt the bytes
			// the Hub forwards.
			if dataLines > 0 {
				data.WriteByte('\n')
			}
			dataLines++
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(trimmed, "data:"), " "))
		}
		if err != nil {
			// Flush any frame the final newline did not close, so a stream
			// that ends abruptly still yields the chunks it did carry.
			flush()
			break
		}
	}

	result := Result{Chunks: chunks}
	switch {
	case teeErr != "":
		return result, fmt.Errorf("%w: %s", ErrTEERefused, teeErr)
	case receipt == "":
		return result, ErrNoReceipt
	}
	signed, err := tee.DecodeReceiptFrame(receipt)
	if err != nil {
		return result, err
	}
	result.Receipt = signed
	return result, nil
}

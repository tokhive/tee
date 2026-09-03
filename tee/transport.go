package tee

import (
	"context"
	"errors"
	"time"
)

// ErrResponseBodyTooLarge means the transport produced more bytes than the job
// was allowed to receive. The response is not discarded — it is truncated, and
// the receipt is signed with CompletionTruncated so a verifier can tell a
// partial response from a whole one.
var ErrResponseBodyTooLarge = errors.New("response body exceeds the allowed size")

// ErrNoTransport means the service was built without a transport. It is a
// wiring error, not a runtime one: a service that cannot reach a provider must
// refuse to be constructed rather than fail every job with a receipt claiming
// the provider never answered.
var ErrNoTransport = errors.New("no transport configured")

// Request is an outbound provider request, assembled from a job spec plus the
// credential the TEE injected.
//
// The headers here are the final set. The transport must not add, rewrite, or
// remove any of them: what it sends is what the receipt will describe, and a
// transport that quietly "helps" would desynchronise the two.
type Request struct {
	Method string
	// Provider names which provider's network egress this request must ride.
	// The data path keys its connection pool by (Provider, Host): two providers
	// hitting the same host still egress through their own agents, so upstream
	// always sees the source IP of the provider whose credential is being spent.
	Provider string
	Host     string
	Path     string
	Query    string
	// Headers is the exact header set to put on the wire. The TEE has already
	// merged the caller's allowed headers with the injected credential.
	Headers map[string]string
	Body    []byte

	// Stream asks for a streaming response. The transport reports each chunk
	// through the Execute callback rather than buffering one body.
	Stream bool

	// MaxResponseBytes is the hard cap on response bytes. The transport is
	// expected to stop at or before this, and the service enforces it
	// regardless of what the transport does.
	MaxResponseBytes uint64

	// Timeout bounds the whole exchange. Zero means no service-level deadline
	// beyond the context.
	Timeout time.Duration
}

// Response is what the provider sent back, minus the body.
//
// The body is never materialised here. It flows through the chunk callback as
// it arrives so that a long stream can be relayed and digested without ever
// being held in memory in full.
type Response struct {
	StatusCode uint32
}

// Transport performs one provider request.
//
// The chunk callback is invoked once per received body chunk, in arrival
// order. It must return an error if the caller wants the exchange stopped;
// the transport should then close the connection. It may be nil when the
// caller does not want the body at all — the service still digests it, which
// is the whole point of the receipt.
//
// Implementations must not retry. A retry would send the credential twice and
// produce a response that no longer corresponds to a single signed execution.
type Transport interface {
	Do(ctx context.Context, req Request, onChunk func(chunk []byte) error) (Response, error)
}

// ChunkFunc is the shape of the per-chunk callback. It exists so that callers
// can name the type in signatures without restating the closure form.
type ChunkFunc func(chunk []byte) error

// Package transport is the outbound network layer of a TokenHive TEE: it turns
// the tee.Transport interface into real HTTP.
//
// The contract it must uphold comes from tee.Request: the header set it
// receives is final. This package adds nothing, rewrites nothing, and follows
// no redirect — every byte it puts on the wire is a byte the TEE decided to
// send, so the signed receipt describes the exchange that actually happened.
//
// Three standard-library behaviours would silently break that contract and
// are explicitly disabled here:
//
//   - Transparent gzip. http.Transport adds Accept-Encoding: gzip and
//     decompresses the response when the caller leaves the header unset. The
//     receipt digests bytes as they arrived; decompressing them would attest
//     a transcript nobody sent.
//   - Retries. http.Transport replays a request whose connection died before
//     a response arrived. A replay sends the credential twice and produces a
//     response that no longer corresponds to a single signed execution. Every
//     request is therefore given a body the standard library cannot rewind
//     (no GetBody), which makes it non-replayable at the source — for bodyless
//     methods too, at the cost of a legal but unusual Content-Length: 0.
//   - Redirect following. A 3xx answered by re-issuing the request elsewhere
//     would spend the injected credential on a host no provider policy ever
//     authorised. Redirects are surfaced, not followed.
//
// Proxy configuration from the environment (HTTP_PROXY and friends) is
// ignored on purpose: an environment variable must never be able to route a
// credential through a machine nobody vetted.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

const (
	// DefaultScheme is used when Config.Scheme is empty.
	DefaultScheme = "https"

	// readBufferSize bounds one chunk handed to the tee relay callback. SSE
	// events are usually far smaller; large buffers only delay the first byte.
	readBufferSize = 32 * 1024

	// idleConnsPerHost is raised above the standard library's default of two
	// because streaming responses hold a connection for the whole duration of
	// a job and a hub dispatches several jobs in parallel.
	idleConnsPerHost = 16
)

// ErrUnsupportedScheme means Config.Scheme was neither http nor https.
var ErrUnsupportedScheme = errors.New("unsupported URL scheme")

// ErrPlaintextNotAllowed means Config.Scheme was "http" without
// Config.AllowPlaintext.
//
// Plaintext is refused by default because of what this transport carries.
// Every request it sends has a provider credential injected into a header, and
// the hop it sends it over may be a Provider Agent — the one component the
// trust model explicitly does not trust. Over http that agent reads the
// credential straight off the wire, and nothing about the failure is visible:
// the request succeeds, the receipt verifies, and the secret is gone. Against a
// configuration mistake the only defence that works is refusing to build.
var ErrPlaintextNotAllowed = errors.New("plaintext scheme requires AllowPlaintext")

// Config assembles an HTTP transport.
type Config struct {
	// Scheme is the URL scheme for provider requests: "https" or "http". It
	// exists because a Spec names a host, not a URL — production traffic is
	// always TLS, while local demos and tests run plain HTTP. Defaults to
	// "https".
	Scheme string

	// AllowPlaintext permits Scheme "http". It exists so that the tests and
	// local demos which genuinely want to inspect bytes on the wire can say so
	// out loud, and so that every other caller — including a production
	// deployment with a mistyped config — fails at construction instead of
	// leaking a credential on its first job. See ErrPlaintextNotAllowed.
	AllowPlaintext bool

	// DialContext, when set, replaces the TCP connection underneath the HTTP
	// client. This is the socket where a Provider Agent pipe plugs in: the
	// agent relays raw TCP bytes, and the TLS session still terminates inside
	// the TEE, so the credential never exists on a wire the TEE does not
	// control.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// TLSClientConfig customises TLS for provider connections. Mainly useful
	// for trusting a test certificate authority.
	TLSClientConfig *tls.Config
}

// HTTP performs provider requests over HTTP/1.1 and HTTP/2 and implements
// tee.Transport.
type HTTP struct {
	scheme string
	client *http.Client
}

// New validates the configuration and returns a ready transport.
func New(cfg Config) (*HTTP, error) {
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = DefaultScheme
	}
	if scheme != "https" && scheme != "http" {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedScheme, scheme)
	}
	if scheme == "http" && !cfg.AllowPlaintext {
		return nil, ErrPlaintextNotAllowed
	}
	base := &http.Transport{
		// Deliberately nil rather than ProxyFromEnvironment: see the package
		// comment. A nil field means no proxy at all.
		Proxy: nil,

		DialContext:     cfg.DialContext,
		TLSClientConfig: cfg.TLSClientConfig,

		// The receipt digests the response as delivered; a transparently
		// decompressed body would desynchronise the proof from the wire.
		DisableCompression: true,

		// Let https connections negotiate HTTP/2. A multiplexed stream can be
		// aborted without disturbing sibling jobs on the same connection.
		ForceAttemptHTTP2: true,

		MaxIdleConnsPerHost: idleConnsPerHost,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	client := &http.Client{
		Transport: base,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		// No client.Timeout: it would cover body consumption and abort a slow
		// but healthy stream mid-transcript. Per-exchange deadlines arrive on
		// the request context instead.
	}
	return &HTTP{scheme: scheme, client: client}, nil
}

// Do performs one provider exchange, relaying body chunks as they arrive.
//
// It implements tee.Transport. Request.Stream makes no difference here: a
// streaming and a buffered response are both relayed chunk by chunk, which is
// exactly what SSE needs. An error from onChunk aborts the exchange and is
// returned as-is; the connection is dropped rather than pooled, because half
// of a transcript must never be reused as if it were whole.
//
// The returned error is nil only when the body was consumed to EOF. Any other
// outcome — dial failure, TLS failure, timeout, mid-body disconnect, consumer
// abort — returns the error alongside the status code observed so far, letting
// the caller decide how much of the exchange it can attest to.
func (h *HTTP) Do(ctx context.Context, req tee.Request, onChunk func(chunk []byte) error) (tee.Response, error) {
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	out, err := buildRequest(ctx, h.scheme, req)
	if err != nil {
		return tee.Response{}, err
	}

	resp, err := h.client.Do(out)
	if err != nil {
		return tee.Response{}, err
	}
	defer resp.Body.Close()

	if onChunk == nil {
		onChunk = func([]byte) error { return nil }
	}

	status := tee.Response{StatusCode: uint32(resp.StatusCode)}
	buf := make([]byte, readBufferSize)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if err := onChunk(buf[:n]); err != nil {
				// The consumer stopped taking the stream. What arrived is
				// returned with the error so the caller can still attest a
				// partial exchange rather than pretend nothing happened.
				return status, err
			}
		}
		if readErr == io.EOF {
			return status, nil
		}
		if readErr != nil {
			return status, readErr
		}
	}
}

// buildRequest renders a tee.Request as an *http.Request without letting the
// standard library editorialise.
func buildRequest(ctx context.Context, scheme string, req tee.Request) (*http.Request, error) {
	target := scheme + "://" + req.Host + req.Path
	if req.Query != "" {
		target += "?" + req.Query
	}

	// url.Parse preserves already-escaped input verbatim (via RawPath), so a
	// percent-encoded path or query reaches the provider exactly as the spec
	// spelled it. The malformed cases that jobs validation forbids — embedded
	// whitespace, stray control characters — are rejected here as parse
	// errors instead of quietly mangled.
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("build request URL: %w", err)
	}

	// Built with a nil body so the constructor applies no body-specific
	// defaults; the bytes are installed below with a type the standard
	// library cannot rewind. See the package comment on retries.
	out, err := http.NewRequestWithContext(ctx, req.Method, parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	out.Body = io.NopCloser(bytes.NewReader(req.Body))
	out.ContentLength = int64(len(req.Body))

	// Header.Set canonicalises the name's case, which is wire-equivalent: the
	// spec's headers describe semantics, and the value bytes are untouched.
	for name, value := range req.Headers {
		out.Header.Set(name, value)
	}
	return out, nil
}

package transport

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// channel is one resident upstream connection: a TLS (or plain, in tests)
// socket with a persistent buffered reader, owned by the TEE and shared across
// jobs while it stays healthy.
//
// A channel is used by exactly one Do at a time. The pool hands it out, the
// caller runs one exchange, then the pool either reuses it (idle) or closes it.
type channel struct {
	conn net.Conn
	br   *bufio.Reader
	pool *channelPool

	// lastUsed is when the channel was last returned to the idle pool, used to
	// reap connections that outlive the idle window.
	lastUsed time.Time
	// wrote counts bytes actually written to this connection. A zero value at
	// exchange failure means nothing left the TEE, so the request is safe to
	// re-dial exactly once.
	wrote int
}

// wroteNothing reports whether no bytes were written to the wire.
func (ch *channel) wroteNothing() bool { return ch.wrote == 0 }

// channelPool is the resident-connection pool for one (provider, host). It
// tracks how many connections are alive and reaps those idle past the window.
type channelPool struct {
	mgr *ChannelManager
	key string

	mu     sync.Mutex
	cond   *sync.Cond
	active int
	closed bool
	idle   []*channel
}

func newChannelPool(mgr *ChannelManager, key string) *channelPool {
	p := &channelPool{mgr: mgr, key: key}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// getIdle returns an idle connection to reuse, or nil when there is none.
func (p *channelPool) getIdle() *channel {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireIdleLocked()
	n := len(p.idle)
	if n == 0 {
		return nil
	}
	ch := p.idle[n-1]
	p.idle = p.idle[:n-1]
	return ch
}

// reserveSlot waits until a slot is free for a brand-new connection, then marks
// it used. Slot accounting mirrors the resident set: an idle connection keeps
// its slot until it is closed.
func (p *channelPool) reserveSlot() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.active >= p.mgr.maxConns && !p.closed {
		p.cond.Wait()
	}
	if p.closed {
		return net.ErrClosed
	}
	p.active++
	return nil
}

// releaseSlot frees a slot reserved by a connection that failed to dial.
func (p *channelPool) releaseSlot() {
	p.mu.Lock()
	p.active--
	p.cond.Signal()
	p.mu.Unlock()
}

// reuse returns a healthy connection to the idle set, refreshing its clock.
func (p *channelPool) reuse(ch *channel) {
	ch.lastUsed = time.Now()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		p.drop(ch)
		return
	}
	p.idle = append(p.idle, ch)
	p.mu.Unlock()
}

// drop closes a connection and frees its slot.
func (p *channelPool) drop(ch *channel) {
	_ = ch.conn.Close()
	p.mu.Lock()
	p.active--
	p.cond.Signal()
	p.mu.Unlock()
}

// expireIdleLocked closes idle connections past the idle window. Caller holds
// p.mu.
func (p *channelPool) expireIdleLocked() {
	now := time.Now()
	kept := p.idle[:0]
	for _, ch := range p.idle {
		if now.Sub(ch.lastUsed) > p.mgr.idleTimeout {
			p.active--
			_ = ch.conn.Close()
			continue
		}
		kept = append(kept, ch)
	}
	p.idle = kept
	if len(kept) < cap(kept) {
		p.cond.Signal()
	}
}

// close closes every idle connection and marks the pool shut so nothing more
// is handed out. Connections currently checked out are unaffected.
func (p *channelPool) close() {
	p.mu.Lock()
	p.closed = true
	p.cond.Broadcast()
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, ch := range idle {
		p.drop(ch)
	}
}

// exchange runs one full provider exchange on this channel: writes the
// hand-serialised request, reads the response, relays body chunks, and reports
// whether the connection may be reused.
//
// The returned status is meaningful even when err is non-nil: a request that
// reached the provider has a status to attest even if the body never finished.
func (ch *channel) exchange(ctx context.Context, req tee.Request, onChunk func([]byte) error, bufSize int) (keep bool, status tee.Response, err error) {
	ch.wrote = 0

	requestBytes, err := buildRequestBytes(req)
	if err != nil {
		return false, tee.Response{}, err
	}

	// Bound the whole exchange by the caller's deadline (already wrapped into
	// ctx by Do). The socket deadline must not survive into the pool, so it is
	// cleared before a reusable connection is returned.
	if dl, ok := ctx.Deadline(); ok {
		_ = ch.conn.SetDeadline(dl)
		defer func() {
			if keep {
				_ = ch.conn.SetDeadline(time.Time{})
			}
		}()
	}

	n, werr := ch.conn.Write(requestBytes)
	ch.wrote = n
	if werr != nil {
		return false, tee.Response{}, fmt.Errorf("write request: %w", werr)
	}
	if n != len(requestBytes) {
		return false, tee.Response{}, io.ErrShortWrite
	}

	// ReadResponse consumes framing from the persistent buffered reader so a
	// Content-Length or chunked body is understood even though we wrote the
	// request bytes ourselves.
	resp, err := http.ReadResponse(ch.br, &http.Request{Method: req.Method})
	if err != nil {
		return false, tee.Response{}, fmt.Errorf("read response headers: %w", err)
	}
	status = tee.Response{StatusCode: uint32(resp.StatusCode)}

	// "Keep" is decided before reading the body: a response signalled close
	// (resp.Close) must not be pooled, whatever happens to the bytes after.
	keep = !resp.Close

	buf := make([]byte, bufSize)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if cerr := onChunk(buf[:n]); cerr != nil {
				_ = resp.Body.Close()
				return false, status, cerr
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			keep = false
			_ = resp.Body.Close()
			return false, status, rerr
		}
	}
	_ = resp.Body.Close()
	return keep, status, nil
}

// buildRequestBytes renders a tee.Request as a raw HTTP/1.1 message without any
// standard-library editorialising.
//
// The response framing (Content-Length, chunked) is understood on read by
// http.ReadResponse; the request itself is written byte-for-byte. There is no
// gzip, no retry, no redirect, and no environment proxy here — every byte is
// one the TEE decided to send, so the signed receipt can describe it exactly.
func buildRequestBytes(req tee.Request) ([]byte, error) {
	var buf bytes.Buffer

	target := req.Path
	if req.Query != "" {
		target += "?" + req.Query
	}

	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", req.Method, target)
	fmt.Fprintf(&buf, "Host: %s\r\n", req.Host)
	fmt.Fprintf(&buf, "Connection: keep-alive\r\n")
	for name, value := range req.Headers {
		fmt.Fprintf(&buf, "%s: %s\r\n", name, value)
	}
	// Always explicit, including zero, so a bodyless request still carries a
	// legal Content-Length: 0 the same way the standard library rendered it.
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(req.Body))
	buf.WriteString("\r\n")
	buf.Write(req.Body)
	return buf.Bytes(), nil
}
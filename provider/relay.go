package provider

import (
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tunnel"
)

// Relay limits and their defaults. The binaries ship these values; a zero in
// AgentConfig means "no bound", the same opt-out shape the Hub's own controls
// use, so an embedder that wants no bound says so by leaving the field alone.
const (
	// DefaultMaxRelayConns is how many relay streams an agent serves at once
	// unless the operator says otherwise. It is the contributor-side bound: the
	// Hub's fair-share cap is per tenant and the TEE's pool is per provider, but
	// only the agent can decide how much of its own machine it will commit.
	DefaultMaxRelayConns = 64

	// DefaultRelayIdle is how long a relay stream may carry nothing before the
	// agent tears it down. It must sit above every bound the Hub and the TEE put
	// on a job — the Hub ships -attempt-timeout 3m and the TEE -request-timeout
	// 2m — so the agent only ever gives up on a stream its counterpart has
	// already given up on, and never cuts one that is merely slow.
	DefaultRelayIdle = 5 * time.Minute
)

// RelayStats is a snapshot of what the agent has relayed and what it has turned
// away. It is the contributor's whole view of what their machine did: the bytes
// themselves are ciphertext the agent is not party to, so counts and outcomes
// are the only facts available.
type RelayStats struct {
	// Active is how many relays are being served right now; Peak is the high
	// water mark since the agent started, which is what sizing MaxRelayConns
	// should be based on.
	Active int64
	Peak   int64

	// Accepted counts relays the agent agreed to serve, Refused counts those it
	// turned away for want of capacity, and IdleClosed counts those it tore down
	// for carrying nothing.
	Accepted   uint64
	Refused    uint64
	IdleClosed uint64

	// RequestBytes are the bytes relayed toward the provider and ResponseBytes
	// those relayed back. Both sides are opaque; only the counts are knowable.
	RequestBytes  uint64
	ResponseBytes uint64
}

// String renders the counters for a log line.
func (s RelayStats) String() string {
	return fmt.Sprintf("relays served=%d refused=%d idle-closed=%d active=%d peak=%d request-bytes=%d response-bytes=%d",
		s.Accepted, s.Refused, s.IdleClosed, s.Active, s.Peak, s.RequestBytes, s.ResponseBytes)
}

// relayMeter accumulates the counters behind RelayStats. Every field is an
// atomic because the relay goroutines touch them concurrently and nothing here
// is worth a mutex on the hot path of a byte copy.
type relayMeter struct {
	active        atomic.Int64
	peak          atomic.Int64
	accepted      atomic.Uint64
	refused       atomic.Uint64
	idleClosed    atomic.Uint64
	requestBytes  atomic.Uint64
	responseBytes atomic.Uint64
}

func (m *relayMeter) enter() {
	n := m.active.Add(1)
	for {
		peak := m.peak.Load()
		if n <= peak || m.peak.CompareAndSwap(peak, n) {
			return
		}
	}
}

func (m *relayMeter) leave() { m.active.Add(-1) }

func (m *relayMeter) snapshot() RelayStats {
	return RelayStats{
		Active:        m.active.Load(),
		Peak:          m.peak.Load(),
		Accepted:      m.accepted.Load(),
		Refused:       m.refused.Load(),
		IdleClosed:    m.idleClosed.Load(),
		RequestBytes:  m.requestBytes.Load(),
		ResponseBytes: m.responseBytes.Load(),
	}
}

// Stats returns the agent's relay counters as of now. Callers are expected to
// poll it (operators log it, tests assert on it) rather than to treat it as a
// stream of events.
func (a *Agent) Stats() RelayStats { return a.meter.snapshot() }

// serveRelay serves one relay stream: gate on the connection cap, dial the
// upstream, then bridge bytes until either side ends or the stream goes idle.
//
// It is deliberately the whole of the agent's behaviour during a relay — no
// frame parsing, no policy, no rewriting. The TEE's TLS session runs through
// here end to end, and anything the agent did to the bytes beyond moving them
// would break a guarantee it cannot see enough to keep.
func (a *Agent) serveRelay(s *tunnel.Stream, up hub.UpstreamOpen) {
	// Bound the contributor's connections. Refused, not queued: a stream the
	// agent will not serve must fail now so the Hub can fall back to another
	// provider, rather than sit waiting on a machine that has already said no.
	// Checked before the dial because holding upstream connections is precisely
	// what the bound exists to limit.
	if a.slots != nil {
		select {
		case a.slots <- struct{}{}:
			defer func() { <-a.slots }()
		default:
			a.meter.refused.Add(1)
			return
		}
	}

	outbound, err := a.dialTarget(up.Host)
	if err != nil {
		return
	}
	defer outbound.Close()

	a.meter.accepted.Add(1)
	a.meter.enter()
	defer a.meter.leave()

	// One clock for the stream, written by whichever direction moves a byte.
	// The watchdog reads it to tell a live relay from an abandoned one.
	var last atomic.Int64
	last.Store(time.Now().UnixNano())

	// Each side counts the bytes it writes, and each side's writes are one
	// direction of the relay: writes to the tunnel stream carry the provider's
	// response, writes to the upstream carry the request. Counting on writes
	// only means every byte is counted exactly once.
	left := relayConn{ReadWriteCloser: s, last: &last, moved: &a.meter.responseBytes}
	right := relayConn{ReadWriteCloser: outbound, last: &last, moved: &a.meter.requestBytes}

	var l, r ioReadWriteCloser = left, right
	if a.cfg.Tap != nil {
		l = tapRWC{rw: left, tap: a.cfg.Tap}
		r = tapRWC{rw: right, tap: a.cfg.Tap}
	}

	stop := a.watchIdle(s, outbound, &last)
	defer stop()

	tunnel.Bridge(l, r)
}

// watchIdle tears a relay down once it has carried nothing for RelayIdle, and
// returns a func that stops watching. It returns a no-op when the watchdog is
// off.
//
// The watchdog exists because a tunnel stream has no read deadline — its Read
// parks on a condition variable — so a relay whose peer has silently gone away
// stays parked, holding the contributor's upstream connection open, until
// something closes the stream. Closing both ends is the release: it unblocks
// the two copies inside Bridge, which is the only way to stop a read that
// cannot time out.
func (a *Agent) watchIdle(stream *tunnel.Stream, upstream net.Conn, last *atomic.Int64) func() {
	idle := a.cfg.RelayIdle
	if idle <= 0 {
		return func() {}
	}
	interval := idle / 2
	if interval <= 0 {
		interval = idle
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, last.Load())) >= idle {
					a.meter.idleClosed.Add(1)
					_ = stream.Close()
					_ = upstream.Close()
					return
				}
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

// relayConn is one side of a relay. It records that bytes moved — so the idle
// watchdog can tell a live stream from an abandoned one — and adds the bytes it
// writes to the direction it belongs to. It changes nothing about the bytes.
type relayConn struct {
	io.ReadWriteCloser
	last  *atomic.Int64  // unix nanos of the last byte in either direction
	moved *atomic.Uint64 // bytes attributed to writes on this side
}

func (c relayConn) Read(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c relayConn) Write(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Write(p)
	if n > 0 {
		c.moved.Add(uint64(n))
		c.touch()
	}
	return n, err
}

func (c relayConn) touch() { c.last.Store(time.Now().UnixNano()) }

// ioReadWriteCloser narrows a full ReadWriteCloser to the surface bridge needs,
// so the tap wrapper and the raw stream both fit the same parameter.
type ioReadWriteCloser interface {
	io.Reader
	io.Writer
	io.Closer
}

// tapRWC mirrors every byte written through it to Tap. It is purely a
// test/demo affordance (see AgentConfig.Tap) and is never used on a production
// path, where the agent must stay a dumb byte pipe.
type tapRWC struct {
	rw  io.ReadWriteCloser
	tap io.Writer
}

func (t tapRWC) Read(p []byte) (int, error) { return t.rw.Read(p) }
func (t tapRWC) Close() error               { return t.rw.Close() }
func (t tapRWC) Write(p []byte) (int, error) {
	if t.tap != nil {
		_, _ = t.tap.Write(p)
	}
	return t.rw.Write(p)
}

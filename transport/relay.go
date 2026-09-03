package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tunnel"
)

// RelayConfig assembles a client-side egress relay to the Hub.
//
// The Provider Agent lives behind a home NAT, so the TEE cannot dial it. It
// dials the Hub instead; the Hub's TeeRelay endpoint re-exports that reverse
// tunnel. This client holds one multiplexed connection to the Hub's relay and
// mints a stream over it for each provider connection the TEE needs. The stream
// is where the TEE's TLS session terminates end to end, so the Hub and the agent
// both see only encrypted bytes.
type RelayConfig struct {
	// URL is the Hub's TeeRelay WebSocket endpoint, e.g.
	// ws://hub/v1/relay.
	URL string

	// Dialer is the WebSocket dialer. Defaults to websocket.DefaultDialer.
	Dialer *websocket.Dialer

	// ConnectTimeout bounds dialing and (re)establishing the tunnel. Zero means
	// 10s.
	ConnectTimeout time.Duration
}

// Relay holds one live tunnel to the Hub's relay endpoint and opens provider
// streams over it. It is safe for concurrent use.
type Relay struct {
	cfg RelayConfig

	mu  sync.Mutex
	tun *tunnel.Multiplexer
}

// NewRelay validates the configuration and returns a ready relay.
func NewRelay(cfg RelayConfig) (*Relay, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("relay: empty URL")
	}
	if cfg.Dialer == nil {
		cfg.Dialer = websocket.DefaultDialer
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	return &Relay{cfg: cfg}, nil
}

// Dial opens a raw egress stream to req and returns it as a net.Conn, so the
// TEE can run its TLS handshake over it exactly as it would over a direct TCP
// socket. If the shared tunnel has dropped, it is re-established once and the
// stream retried; an error past that is returned as-is.
func (r *Relay) Dial(ctx context.Context, provider, host string) (net.Conn, error) {
	conn, used, err := r.dialOnce(ctx, provider, host)
	if err == nil {
		return conn, nil
	}
	// The tunnel we dialed over is dead; drop it so the next call (or this
	// retry) builds a fresh one, then try exactly once more. Nothing has been
	// spent because no provider bytes crossed the wire before the stream existed.
	r.resetIf(used)
	conn, _, err = r.dialOnce(ctx, provider, host)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (r *Relay) dialOnce(ctx context.Context, provider, host string) (net.Conn, *tunnel.Multiplexer, error) {
	tun, err := r.tunnel(ctx)
	if err != nil {
		return nil, nil, err
	}
	meta, err := json.Marshal(hub.RelayOpen{Provider: provider, Host: host})
	if err != nil {
		return nil, tun, err
	}
	s, err := tun.Dial(meta)
	if err != nil {
		return nil, tun, err
	}
	return streamConn{Stream: s}, tun, nil
}

// tunnel returns the live tunnel, dialing the Hub relay endpoint if none exists.
func (r *Relay) tunnel(ctx context.Context) (*tunnel.Multiplexer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tun != nil {
		return r.tun, nil
	}
	dialCtx, cancel := context.WithTimeout(ctx, r.cfg.ConnectTimeout)
	defer cancel()
	conn, resp, err := r.cfg.Dialer.DialContext(dialCtx, r.cfg.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("dial relay tunnel: %w", err)
	}
	if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		return nil, fmt.Errorf("relay tunnel refused: %s", resp.Status)
	}
	tun := tunnel.New(tunnel.WrapWS(conn), tunnel.High)
	r.tun = tun
	return tun, nil
}

// resetIf drops a tunnel that failed to serve a stream, but only when it is
// still the tunnel the relay owns. A concurrent Dial may already have torn the
// dead tunnel down and rebuilt a fresh one; resetting the stale reference then
// would tear that healthy tunnel down too. Fine-grained: a controller that never
// dialed the failed tunnel leaves it untouched, so a single stream failure never
// kills unrelated streams.
func (r *Relay) resetIf(tun *tunnel.Multiplexer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tun == tun {
		_ = r.tun.Close()
		r.tun = nil
	}
}

// Close tears down the relay tunnel. In-flight streams are broken; holders see
// io.EOF on read and error on write.
func (r *Relay) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tun != nil {
		_ = r.tun.Close()
		r.tun = nil
	}
	return nil
}

// streamConn adapts a tunnel.Stream to net.Conn so the TEE can run an HTTP/TLS
// session over a relayed stream as if it were a TCP socket. Deadline and address
// bookkeeping have no meaning on a multiplexed tunnel, so they are inert.
type streamConn struct {
	*tunnel.Stream
}

func (c streamConn) LocalAddr() net.Addr              { return relayAddr }
func (c streamConn) RemoteAddr() net.Addr             { return relayAddr }
func (c streamConn) SetDeadline(time.Time) error      { return nil }
func (c streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c streamConn) SetWriteDeadline(time.Time) error { return nil }

// relayAddr is the fixed address relayed streams report; deadlines and address
// bookkeeping have no meaning on a multiplexed tunnel.
var relayAddr = relayAddrValue{}

type relayAddrValue struct{}

func (relayAddrValue) Network() string { return "relay" }
func (relayAddrValue) String() string  { return "hub-relay" }

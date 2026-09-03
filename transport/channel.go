package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// ChannelConfig assembles a ChannelManager.
type ChannelConfig struct {
	// Endpoints resolves a provider name to its egress Agent address. Required.
	Endpoints *EndpointRegistry

	// Scheme is "https" or "http" for provider requests. Defaults to "https".
	Scheme string

	// AllowPlaintext permits Scheme "http". Plaintext carries a provider
	// credential that the Agent can read off the wire, so it is refused unless
	// explicitly enabled — same rule as the old http.go, kept for the tests and
	// demos that want to inspect bytes.
	AllowPlaintext bool

	// TLSClientConfig customises TLS for provider connections, e.g. trusting a
	// test CA. Only the trust roots and a minimum version matter; handshake and
	// record layers are standard.
	TLSClientConfig *tls.Config

	// IdleTimeout is how long an idle pooled connection is kept before being
	// closed. This is what makes a connection "resident": while the window is
	// open, every user call for the same provider+host reuses the same TLS
	// session instead of re-handshaking. Default 5 minutes.
	IdleTimeout time.Duration

	// MaxConnsPerHost bounds concurrent pooled connections per (provider, host).
	// Beyond it, acquisition waits for a slot. Zero means 32.
	MaxConnsPerHost int
}

// DefaultScheme is used when ChannelConfig.Scheme is empty.
const DefaultScheme = "https"

const (
	// defaultReadBufferSize bounds one chunk handed to the tee relay callback.
	defaultReadBufferSize = 32 * 1024
	// defaultIdleTimeout is how long a resident connection is kept idle.
	defaultIdleTimeout = 5 * time.Minute
	// defaultMaxConns bounds resident connections per (provider, host).
	defaultMaxConns = 32
)

// ErrUnsupportedScheme means ChannelConfig.Scheme was neither http nor https.
var ErrUnsupportedScheme = errors.New("unsupported URL scheme")

// ErrPlaintextNotAllowed means ChannelConfig.Scheme was "http" without
// ChannelConfig.AllowPlaintext.
//
// Plaintext is refused by default because of what the data path carries. Every
// request has a provider credential injected into a header, and the hop it
// sends it over may be a Provider Agent — the one component the trust model
// explicitly does not trust. Over http that agent reads the credential straight
// off the wire, and nothing about the failure is visible: the request succeeds,
// the receipt verifies, and the secret is gone. Against a configuration mistake
// the only defence that works is refusing to build.
var ErrPlaintextNotAllowed = errors.New("plaintext scheme requires AllowPlaintext")

// ChannelManager performs provider requests over explicitly-managed,
// long-lived TLS connections. It implements tee.Transport.
//
// Unlike the net/http-backed transport, a connection here is a first-class
// object: the TEE holds it, keys its pool by (Provider, Host), and reuses the
// exact same TLS session across jobs while the idle window is open. The Hub
// never holds this connection and never sees a TLS key — it only receives the
// decrypted bytes through Execute's chunk callback, which is precisely the
// "connection resident in the TEE" split the design mandates.
type ChannelManager struct {
	cfg ChannelConfig

	scheme      string
	maxConns    int
	idleTimeout time.Duration
	readBufSize int

	mu    sync.Mutex
	pools map[string]*channelPool
}

// pairKey identifies one pool: a provider's egress plus one upstream host.
type pairKey struct {
	provider string
	host     string
}

func (p pairKey) String() string { return p.provider + "\x00" + p.host }

// NewChannelManager validates the configuration and returns a ready manager.
func NewChannelManager(cfg ChannelConfig) (*ChannelManager, error) {
	if cfg.Endpoints == nil {
		return nil, errors.New("channel manager: no endpoint registry")
	}
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
	idle := cfg.IdleTimeout
	if idle <= 0 {
		idle = defaultIdleTimeout
	}
	maxConns := cfg.MaxConnsPerHost
	if maxConns <= 0 {
		maxConns = defaultMaxConns
	}
	return &ChannelManager{
		cfg:         cfg,
		scheme:      scheme,
		maxConns:    maxConns,
		idleTimeout: idle,
		readBufSize: defaultReadBufferSize,
		pools:       make(map[string]*channelPool),
	}, nil
}

// Do performs one provider exchange on a pooled connection, relaying body
// chunks as they arrive. It implements tee.Transport.
//
// Acquisition: an idle connection for (Provider, Host) is reused if one exists;
// otherwise a new one is dialed through the provider's agent (if any) and
// TLS-handshaken inside the TEE.
//
// Outcome: a request that wrote zero bytes to a dead pooled connection is
// re-dialed once — nothing reached the agent or provider, so nothing was spent
// twice. Once bytes are on the wire, failures are returned as-is and the
// connection is dropped, never pooled back half-open.
//
// An error from onChunk aborts the read; the connection is discarded because
// half a transcript must never be reused as if it were whole.
func (m *ChannelManager) Do(ctx context.Context, req tee.Request, onChunk func(chunk []byte) error) (tee.Response, error) {
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}
	if onChunk == nil {
		onChunk = func([]byte) error { return nil }
	}

	ch, err := m.acquire(ctx, req)
	if err != nil {
		return tee.Response{}, err
	}
	keep, status, err := ch.exchange(ctx, req, onChunk, m.readBufSize)
	if err != nil && ch.wroteNothing() {
		// A dead pooled socket cost this request nothing but the excursion.
		// Nothing left the TEE, so re-dial exactly once instead of failing.
		m.release(ch, false)
		ch, err = m.acquire(ctx, req)
		if err != nil {
			return tee.Response{}, err
		}
		keep, status, err = ch.exchange(ctx, req, onChunk, m.readBufSize)
	}
	m.release(ch, keep)
	return status, err
}

// Close closes every pooled connection and stops future pooling. In-flight
// exchanges are unaffected.
func (m *ChannelManager) Close() error {
	m.mu.Lock()
	pools := make([]*channelPool, 0, len(m.pools))
	for _, p := range m.pools {
		pools = append(pools, p)
	}
	m.pools = make(map[string]*channelPool)
	m.mu.Unlock()
	for _, p := range pools {
		p.close()
	}
	return nil
}

// OpenSession establishes a transparent, long-lived provider session via an
// HTTP Upgrade (e.g. WebSocket) and returns it as an opaque byte pipe. It
// implements tee.SessionOpener.
//
// Unlike Do, this connection is NOT pooled: a session is consumed by whoever
// opened it and is closed when they are done. It still egresses through the
// provider's Agent and TLS terminates inside the TEE, so the isolation is
// identical to any other provider traffic. After the upgrade the connection is
// pure transport — bytes in, bytes out — with every frame of the upstream
// protocol left to the caller.
func (m *ChannelManager) OpenSession(ctx context.Context, req tee.Request) (tee.SessionConn, error) {
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	endpoint, ok := m.cfg.Endpoints.Endpoint(req.Provider)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownEndpoint, req.Provider)
	}
	conn, err := m.dialTCP(ctx, endpoint, req.Host)
	if err != nil {
		return nil, err
	}

	// Bound the handshake by the caller's deadline, then lift it so the session
	// can live arbitrarily long once established.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
		defer func() { _ = conn.SetDeadline(time.Time{}) }()
	}

	br := bufio.NewReader(conn)
	if err := m.upgrade(ctx, conn, br, req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &Session{conn: conn, br: br}, nil
}

// upgrade writes the HTTP Upgrade request and verifies the provider answered
// 101 Switching Protocols. On any other status the connection is refused.
func (m *ChannelManager) upgrade(ctx context.Context, conn net.Conn, br *bufio.Reader, req tee.Request) error {
	requestBytes, err := buildUpgradeBytes(req)
	if err != nil {
		return err
	}
	n, err := conn.Write(requestBytes)
	if err != nil {
		return fmt.Errorf("write upgrade request: %w", err)
	}
	if n != len(requestBytes) {
		return io.ErrShortWrite
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: req.Method})
	if err != nil {
		return fmt.Errorf("read upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("provider refused upgrade: %s", resp.Status)
	}
	return nil
}

func (m *ChannelManager) poolFor(req tee.Request) *channelPool {
	key := pairKey{provider: req.Provider, host: req.Host}.String()
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.pools[key]; ok {
		return p
	}
	p := newChannelPool(m, key)
	m.pools[key] = p
	return p
}

// acquire returns an open channel, reusing an idle one or dialing a new one.
func (m *ChannelManager) acquire(ctx context.Context, req tee.Request) (*channel, error) {
	pool := m.poolFor(req)
	if ch := pool.getIdle(); ch != nil {
		return ch, nil
	}
	return m.dial(ctx, pool, req)
}

// release returns an open channel to its pool, or closes it when keep is false.
func (m *ChannelManager) release(ch *channel, keep bool) {
	if !keep {
		ch.pool.drop(ch)
		return
	}
	ch.pool.reuse(ch)
}

func (m *ChannelManager) dial(ctx context.Context, pool *channelPool, req tee.Request) (*channel, error) {
	endpoint, ok := m.cfg.Endpoints.Endpoint(req.Provider)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownEndpoint, req.Provider)
	}

	// Reserve a slot for a brand-new connection before dialing. This bounds the
	// resident set per (provider, host); a caller blocked here waits until an
	// existing connection dies and frees its slot.
	if err := pool.reserveSlot(); err != nil {
		return nil, err
	}
	conn, err := m.dialTCP(ctx, endpoint, req.Host)
	if err != nil {
		pool.releaseSlot()
		return nil, err
	}
	return &channel{conn: conn, br: bufio.NewReader(conn), pool: pool}, nil
}

// dialTCP opens the raw pipe to req.Host, optionally through the provider's
// agent, and wraps it in TLS when the scheme needs it.
func (m *ChannelManager) dialTCP(ctx context.Context, endpoint Endpoint, host string) (net.Conn, error) {
	var conn net.Conn
	var err error
	if endpoint.AgentAddr != "" {
		conn, err = SOCKS5Dialer(endpoint.AgentAddr, endpoint.Auth())(ctx, "tcp", host)
	} else {
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return nil, err
	}
	if m.scheme != "https" {
		return conn, nil
	}

	tlsCfg := &tls.Config{
		ServerName: serverName(host),
		RootCAs:    m.cfg.TLSClientConfig.RootCAs,
		MinVersion: m.cfg.TLSClientConfig.MinVersion,
		// Explicit connection-resident model: ALPN locked to HTTP/1.1 so one
		// connection carries exactly one in-flight request and is reusable
		// frame-to-frame. HTTP/2 multiplexing would blur the "one connection =
		// one job" boundary that the pool relies on.
		NextProtos: []string{"http/1.1"},
	}
	tconn := tls.Client(conn, tlsCfg)
	if err := tconn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tconn, nil
}

// serverName strips the port from a host for use as the TLS ServerName.
func serverName(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

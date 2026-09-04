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

	// RelayURL, when set, is the Hub's TeeRelay WebSocket endpoint. The manager
	// then dials every provider connection as a stream over one persistent hub
	// relay tunnel (the Provider Agent dials the Hub in reverse). TLS still
	// terminates in the TEE over the stream, so the connection-resident split is
	// unchanged. When empty, the manager dials req.Host directly (used by the
	// embedded transport tests and colocated simulation runs).
	RelayURL string
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
	relay *Relay

	// stopReaper halts the background idle sweeper, which reaps idle
	// connections whose window has elapsed even when no new request ever comes
	// to prod them. Guarded by stopReaperDo so Close is safe to call twice.
	stopReaper   chan struct{}
	stopReaperDo sync.Once
}

// reapInterval is how often the idle sweeper runs. It is a fraction of the
// idle window so that a connection is closed no later than ~1.5 windows after
// its last use, without the sweeper itself being busy.
func (m *ChannelManager) reapInterval() time.Duration {
	interval := m.idleTimeout / 2
	if interval < 100*time.Millisecond {
		return 100 * time.Millisecond
	}
	if interval > 30*time.Second {
		return 30 * time.Second
	}
	return interval
}

// pairKey identifies one pool: a provider's egress plus one upstream host.
type pairKey struct {
	provider string
	host     string
}

func (p pairKey) String() string { return p.provider + "\x00" + p.host }

// NewChannelManager validates the configuration and returns a ready manager.
func NewChannelManager(cfg ChannelConfig) (*ChannelManager, error) {
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
	m := &ChannelManager{
		cfg:         cfg,
		scheme:      scheme,
		maxConns:    maxConns,
		idleTimeout: idle,
		readBufSize: defaultReadBufferSize,
		pools:       make(map[string]*channelPool),
	}
	if cfg.RelayURL != "" {
		r, err := NewRelay(RelayConfig{URL: cfg.RelayURL})
		if err != nil {
			return nil, err
		}
		m.relay = r
	}
	m.startReaper()
	return m, nil
}

// startReaper launches the background idle sweeper. It exists so the IdleTimeout
// is honoured even when a pool is never asked for a connection again: without
// it, an idle resident connection would live until process exit, which is
// precisely the resource leak the window exists to prevent.
func (m *ChannelManager) startReaper() {
	m.stopReaper = make(chan struct{})
	go func() {
		ticker := time.NewTicker(m.reapInterval())
		defer ticker.Stop()
		for {
			select {
			case <-m.stopReaper:
				return
			case <-ticker.C:
				m.reapIdle()
			}
		}
	}()
}

// reapIdle walks every pool and closes connections idle past the window. The
// pool snapshot is taken under m.mu; each pool is swept under its own lock.
func (m *ChannelManager) reapIdle() {
	m.mu.Lock()
	pools := make([]*channelPool, 0, len(m.pools))
	for _, p := range m.pools {
		pools = append(pools, p)
	}
	m.mu.Unlock()
	for _, p := range pools {
		p.expireIdle()
	}
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

// Close stops the idle sweeper, closes every pooled connection, and stops
// future pooling. In-flight exchanges are unaffected.
func (m *ChannelManager) Close() error {
	if m.stopReaper != nil {
		m.stopReaperDo.Do(func() { close(m.stopReaper) })
	}
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
	if m.relay != nil {
		_ = m.relay.Close()
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

	conn, err := m.dialTCP(ctx, req)
	if err != nil {
		return nil, err
	}

	// Bound the handshake by the caller's deadline, then lift it so the session
	// can live arbitrarily long once established.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	// A plain cancellation (no deadline) must still abort a handshake that is
	// blocked on a silent peer. The poke is stopped once the session is
	// established — from then on the session's own idle watchdog governs, not
	// the request context that opened it. The clear runs after the stop so a
	// poke that fired at the worst moment cannot leave a stale deadline on a
	// healthy session.
	stopOnCancel := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer func() {
		stopOnCancel()
		_ = conn.SetDeadline(time.Time{})
	}()

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
	// Reserve a slot for a brand-new connection before dialing. This bounds the
	// resident set per (provider, host); a caller blocked here waits until an
	// existing connection dies and frees its slot.
	if err := pool.reserveSlot(); err != nil {
		return nil, err
	}
	conn, err := m.dialTCP(ctx, req)
	if err != nil {
		pool.releaseSlot()
		return nil, err
	}
	return &channel{conn: conn, br: bufio.NewReader(conn), pool: pool}, nil
}

// dialTCP opens the raw pipe to req.Host and wraps it in TLS when the scheme
// needs it. Through the Hub relay the pipe is a stream over the provider's
// reverse tunnel; without a relay it is a direct TCP connection (transport
// tests and colocated simulation runs). In both cases TLS terminates here,
// inside the TEE, and the provider name never appears on the wire.
func (m *ChannelManager) dialTCP(ctx context.Context, req tee.Request) (net.Conn, error) {
	var conn net.Conn
	var err error
	if m.relay != nil {
		conn, err = m.relay.Dial(ctx, req.Provider, req.Host)
	} else {
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", req.Host)
	}
	if err != nil {
		return nil, err
	}
	if m.scheme != "https" {
		return conn, nil
	}
	return m.wrapTLS(ctx, conn, req.Host)
}

// wrapTLS upgrades a raw provider pipe to TLS with the config the manager was
// given. The trust roots determine what the TEE will attest against; only the
// roots and a minimum version are customised, and the handshake/record layers
// are standard.
func (m *ChannelManager) wrapTLS(ctx context.Context, conn net.Conn, host string) (net.Conn, error) {
	tlsCfg := &tls.Config{
		ServerName: serverName(host),
		// The caller's TLS config is optional: nil means the platform defaults,
		// which in production is the system trust store — the C4 checklist's
		// "Channel TLS roots = system roots" requirement is simply the default
		// here. Only tests and the local simulation supply a custom root pool.
		MinVersion: tls.VersionTLS12,
		// Explicit connection-resident model: ALPN locked to HTTP/1.1 so one
		// connection carries exactly one in-flight request and is reusable
		// frame-to-frame. HTTP/2 multiplexing would blur the "one connection =
		// one job" boundary that the pool relies on.
		NextProtos: []string{"http/1.1"},
	}
	if m.cfg.TLSClientConfig != nil {
		tlsCfg.RootCAs = m.cfg.TLSClientConfig.RootCAs
		if m.cfg.TLSClientConfig.MinVersion != 0 {
			tlsCfg.MinVersion = m.cfg.TLSClientConfig.MinVersion
		}
		if len(m.cfg.TLSClientConfig.ServerName) > 0 {
			tlsCfg.ServerName = m.cfg.TLSClientConfig.ServerName
		}
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

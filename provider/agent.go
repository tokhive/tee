// Package provider implements the TokenHive Provider Agent: the process a quota
// contributor runs on their own machine so a TEE can egress through their
// network.
//
// The agent lives behind a home NAT, so it cannot be dialed: it dials the Hub
// and keeps one multiplexed WebSocket open (what the design calls the reverse
// tunnel). Registering with the Hub's AgentGate makes it online and schedulable;
// while that tunnel stays up, the Hub routes this provider's egress through it.
// The shared key it presents at dial-in is the only thing telling the Hub that
// this machine may claim to egress for its provider.
//
// The agent is deliberately dumb. For each relay stream the Hub opens on its
// tunnel it dials the named upstream host once — checked against a fixed
// allowlist — and then copies bytes in both directions without inspecting them.
// It cannot read the traffic it relays: the TEE's TLS session with the AI
// provider is end to end, and the agent sees only the encrypted bytes of a
// session it is not party to.
//
// What the agent does enforce, and all it enforces:
//
//   - The allowlist. An agent that forwarded to arbitrary hosts would turn a
//     contributor's machine into a general-purpose proxy; the allowlist keeps
//     the exposure to "AI provider endpoints", which is what the contributor
//     signed up for.
//
// Absent by design (production concerns, noted for later milestones):
// connection caps, idle timeouts, and usage metering. The agent is a simulation
// milestone component; a contributor-facing release needs all three.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tunnel"
)

// Agent errors.
var (
	ErrEmptyAllowlist = errors.New("provider agent: allowlist must not be empty")
	ErrNoGateURL      = errors.New("provider agent: no Hub gate URL")
	ErrNoSharedKey    = errors.New("provider agent: no shared key")
	ErrNoProvider     = errors.New("provider agent: no provider name")
)

// AgentConfig assembles an Agent.
type AgentConfig struct {
	// HubGateURL is the Hub's AgentGate WebSocket endpoint the agent dials to
	// come online, e.g. ws://127.0.0.1:18085/v1/agent. Required.
	HubGateURL string

	// SharedKey is the preset shared secret the agent presents at dial-in. It
	// must match the Hub's AgentSecret or the gate refuses the tunnel. Required.
	SharedKey []byte

	// Self announces the agent on registration: which provider it egresses for,
	// an optional display label, and — when SelfPrice is set — the price it
	// wants to charge. A nil SelfPrice means the agent accepts the Hub's
	// platform default. Required: Provider must be set.
	Self hub.AgentRegister

	// Credential is the provider's access token together with the header it is
	// presented in. It is the one secret the seller owns; it never appears on
	// the wire in plaintext. When set, each registration fetches the Hub's
	// published TEE inbox key, seals this credential to it (tee.Envelope), and
	// the Hub relays only the ciphertext onward. A zero Credential (no token)
	// registers without an envelope — the Hub's gate refuses such registrations
	// when it hosts agents, so this only matters for agent-only relay tests.
	Credential tee.Secret

	// AllowedTargets lists the exact "host:port" upstreams the agent will dial.
	// Anything else is refused before a single byte egresses. It must be
	// non-empty: an agent that forwards anywhere is a public proxy.
	AllowedTargets []string

	// ConnectTimeout bounds dialing the Hub and dialing each upstream. Zero means
	// 10s.
	ConnectTimeout time.Duration

	// ReconnectDelay pauses between reconnect attempts after the tunnel drops.
	// Zero means 1s.
	ReconnectDelay time.Duration

	// DialTarget replaces the outbound upstream dial. Test injection point; nil
	// uses the standard dialer.
	DialTarget func(ctx context.Context, network, addr string) (net.Conn, error)

	// Tap, when set, receives a copy of every byte the agent relays on either
	// wire (the tunnel to the Hub and the tunnel to the provider). It is a
	// test/demo affordance only — used by the local simulation to prove the
	// agent sees only the encrypted bytes of a TLS session it is not party to.
	// Never set in production; the relay must stay dumb.
	Tap io.Writer
}

// Agent is the Provider Agent reverse-tunnel client. It is safe to Run once.
type Agent struct {
	cfg AgentConfig
	hdr http.Header
}

// NewAgent validates the configuration and returns a ready agent.
func NewAgent(cfg AgentConfig) (*Agent, error) {
	if cfg.HubGateURL == "" {
		return nil, ErrNoGateURL
	}
	if len(cfg.SharedKey) == 0 {
		return nil, ErrNoSharedKey
	}
	if cfg.Self.Provider == "" {
		return nil, ErrNoProvider
	}
	if len(cfg.AllowedTargets) == 0 {
		return nil, ErrEmptyAllowlist
	}
	if cfg.Credential.Token != "" {
		if err := cfg.Credential.Validate(); err != nil {
			return nil, err
		}
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.ReconnectDelay <= 0 {
		cfg.ReconnectDelay = time.Second
	}
	a := &Agent{cfg: cfg}
	a.hdr = http.Header{}
	a.hdr.Set(hub.AgentKeyHeader, string(cfg.SharedKey))
	return a, nil
}

// Run keeps the agent online until ctx is cancelled, reconnecting after every
// tunnel drop. register is one full connection cycle: dial, register, and relay
// until the tunnel ends.
//
// The context also interrupts an in-flight cycle: without it, a graceful stop
// would leave the tunnel open (runOnce blocks in io.Copy on the control
// stream) and the Hub would keep the provider online. runOnce registers the
// interrupt with the live tunnel so cancellation closes the connection, which
// is exactly what a killed process does — the Hub sees the drop and revokes
// the credential.
func (a *Agent) Run(ctx context.Context) error {
	for {
		err := a.runOnce(ctx)
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(a.cfg.ReconnectDelay):
		}
	}
}

// runOnce runs one connection cycle: dial the Hub gate, register, and relay
// until the tunnel drops. It returns when the tunnel ends so Run can reconnect.
func (a *Agent) runOnce(ctx context.Context) error {
	dialer := websocket.Dialer{HandshakeTimeout: a.cfg.ConnectTimeout}
	conn, resp, err := dialer.DialContext(ctx, a.cfg.HubGateURL, a.hdr)
	if err != nil {
		return fmt.Errorf("dial hub gate: %w", err)
	}
	defer conn.Close()
	if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("hub gate: %s", resp.Status)
	}

	mux := tunnel.New(tunnel.WrapWS(conn), tunnel.High)
	defer mux.Close()
	mux.Serve(a.handleRelay)

	// Interrupt this cycle when the run context is cancelled: closing the
	// connection unblocks the control-stream copy below and tells the Hub the
	// agent went offline (which revokes the credential).
	stopOnCancel := context.AfterFunc(ctx, func() { _ = mux.Close() })
	defer stopOnCancel()

	reg, err := a.register()
	if err != nil {
		return err
	}
	register, err := json.Marshal(reg)
	if err != nil {
		return fmt.Errorf("encode registration: %w", err)
	}
	control, err := mux.Dial(register)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	defer control.Close()

	// The control stream is the agent's lease on being online: it stays open
	// until the Hub tears the tunnel down or the connection drops, either of
	// which returns here and lets Run reconnect.
	if _, err := io.Copy(io.Discard, control); err != nil {
		return err
	}
	return nil
}

// register seals the credential to the current TEE inbox key and returns the
// control-stream payload. Fetching and re-encrypting on every connection cycle
// keeps registrations correct across TEE restarts: a fresh TEE generates a
// fresh inbox key, and the agent's next dial picks it up.
//
// A configuration without a token skips the fetch entirely and registers
// without an envelope (relay-only deployments, tests).
func (a *Agent) register() (hub.AgentRegister, error) {
	reg := a.cfg.Self
	if a.cfg.Credential.Token == "" {
		return reg, nil
	}

	pub, err := a.credentialKey()
	if err != nil {
		return reg, err
	}
	envelope, err := tee.EncryptCredential(pub, reg.Provider, a.cfg.Credential)
	if err != nil {
		return reg, fmt.Errorf("seal credential: %w", err)
	}
	reg.Credential = &envelope
	return reg, nil
}

// credentialKey fetches the Hub's published TEE inbox public key. The Hub
// relays it from its credential plane; the agent never needs the TEE's address
// or its attestation — it encrypts to whatever key the Hub is currently
// delivering credentials to.
func (a *Agent) credentialKey() (tee.InboxPublic, error) {
	keyURL := a.hubHTTPURL() + "/v1/credential-key"
	pub, err := tee.CredentialKeyRequest(context.Background(), a.httpClient(), keyURL)
	if err != nil {
		return pub, fmt.Errorf("fetch inbox key: %w", err)
	}
	return pub, nil
}

// hubHTTPURL rewrites the dialed WebSocket gate URL into the Hub's HTTP base,
// e.g. ws://hub:port/v1/agent -> http://hub:port.
func (a *Agent) hubHTTPURL() string {
	return strings.TrimSuffix(strings.Replace(a.cfg.HubGateURL, "ws://", "http://", 1), "/v1/agent")
}

// httpClient returns a bounded client for the control-plane HTTP calls the
// agent makes (credential-key fetch). It is deliberately separate from the
// WebSocket dialer: same server, different hop.
func (a *Agent) httpClient() *http.Client {
	return &http.Client{Timeout: a.cfg.ConnectTimeout}
}

// handleRelay bridges one Hub-opened relay stream to the named upstream. It runs
// on its own goroutine (the tunnel spawns each open) and only ever moves bytes.
func (a *Agent) handleRelay(s *tunnel.Stream, open []byte) {
	defer s.Close()
	var up hub.UpstreamOpen
	if err := json.Unmarshal(open, &up); err != nil {
		return
	}
	if up.Host == "" || !a.allows(up.Host) {
		return
	}
	outbound, err := a.dialTarget(up.Host)
	if err != nil {
		return
	}
	defer outbound.Close()

	// After the relay opens, the only bytes on either wire are TLS records (the
	// TEE's session with the provider). Mirror them to the tap, if configured,
	// so a test can prove the agent relays ciphertext and never the credential
	// the TEE injected inside that session.
	var left, right ioReadWriteCloser = s, outbound
	if a.cfg.Tap != nil {
		left = tapRWC{rw: s, tap: a.cfg.Tap}
		right = tapRWC{rw: outbound, tap: a.cfg.Tap}
	}
	tunnel.Bridge(left, right)
}

// allows reports whether host is on the allowlist. Exact host:port match only:
// patterns would invite "close enough" targets that were never meant to be
// allowed.
func (a *Agent) allows(host string) bool {
	for _, allowed := range a.cfg.AllowedTargets {
		if host == allowed {
			return true
		}
	}
	return false
}

// dialTarget opens the outbound connection to the upstream host.
func (a *Agent) dialTarget(host string) (net.Conn, error) {
	dial := a.cfg.DialTarget
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.ConnectTimeout)
	defer cancel()
	conn, err := dial(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", host, err)
	}
	return conn, nil
}

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

// Package provider implements the TokenHive Provider Agent: the process a
// quota contributor runs on their own machine so a TEE can egress through
// their network.
//
// The agent is deliberately dumb. It speaks just enough SOCKS5 (RFC 1928
// CONNECT with optional RFC 1929 username/password authentication) to accept
// a tunnel, checks the requested target against a fixed allowlist, and then
// copies bytes in both directions without inspecting them. It cannot read the
// traffic it relays: the TEE's TLS session with the AI provider is end to
// end, and the agent sees only the encrypted bytes of a session it is not
// party to.
//
// What the agent does enforce, and all it enforces:
//
//   - Authentication, when configured, so a discovered agent is not an open
//     relay for whoever finds it.
//   - The allowlist. An agent that forwarded to arbitrary hosts would turn a
//     contributor's machine into a general-purpose proxy; the allowlist keeps
//     the exposure to "AI provider endpoints", which is what the contributor
//     signed up for.
//
// Absent by design (production concerns, noted for later milestones):
// connection caps, idle timeouts, and usage metering. The agent is a M2 demo
// component; a contributor-facing release needs all three.
package provider

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// SOCKS5 protocol constants, server side. See the note in the transport
// package about the two halves owning their own copy.
const (
	socks5Version        = 5
	socks5MethodNone     = 0x00
	socks5MethodUserPass = 0x02
	socks5MethodReject   = 0xFF
	socks5AuthVersion    = 1

	socks5CmdConnect = 0x01

	socks5RepSucceeded      = 0x00
	socks5RepRefused        = 0x01
	socks5RepNotAllowed     = 0x02
	socks5RepCmdUnsupported = 0x07
	socks5RepAtypBad        = 0x08

	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04
)

// Agent errors.
var (
	ErrEmptyAllowlist = errors.New("provider agent: allowlist must not be empty")
	ErrAuthRequired   = errors.New("provider agent: authentication required but no credentials configured")
)

// Auth is the username/password pair an agent demands before it will open a
// tunnel (RFC 1929). Comparison is constant-time: the credentials arrive over
// the network and login attempts should not double as an oracle.
type Auth struct {
	Username string
	Password string
}

// matches reports whether the presented credentials are the configured ones.
func (a *Auth) matches(username, password []byte) bool {
	u := []byte(a.Username)
	p := []byte(a.Password)
	return constantTimeEqual(u, username) && constantTimeEqual(p, password)
}

// AgentConfig assembles an Agent.
type AgentConfig struct {
	// Auth, when set, requires every connection to authenticate first. Leave
	// nil only for loopback demos.
	Auth *Auth

	// AllowedTargets lists the exact "host:port" destinations the agent will
	// dial. Anything else is refused before a single byte egresses. It must
	// be non-empty: an agent that forwards anywhere is a public proxy.
	AllowedTargets []string

	// ConnectTimeout bounds dialing the target provider. Zero means 10s.
	ConnectTimeout time.Duration

	// DialTarget replaces the outbound dial. Test injection point; nil uses
	// the standard dialer.
	DialTarget func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Agent is the Provider Agent server. It is safe to Serve once.
type Agent struct {
	cfg AgentConfig

	mu     sync.Mutex
	ln     net.Listener
	closed bool
}

// NewAgent validates the configuration and returns a ready agent.
func NewAgent(cfg AgentConfig) (*Agent, error) {
	if len(cfg.AllowedTargets) == 0 {
		return nil, ErrEmptyAllowlist
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	return &Agent{cfg: cfg}, nil
}

// ListenAndServe listens on addr and serves until Close is called.
func (a *Agent) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("provider agent: listen: %w", err)
	}
	return a.Serve(ln)
}

// Serve accepts connections on ln until Close is called or ln fails.
func (a *Agent) Serve(ln net.Listener) error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		_ = ln.Close()
		return errors.New("provider agent: serve on a closed agent")
	}
	a.ln = ln
	a.mu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			a.mu.Lock()
			closed := a.closed
			a.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("provider agent: accept: %w", err)
		}
		go a.handle(conn)
	}
}

// Close stops the listener. In-flight pipes finish on their own: cutting an
// active transcript mid-relay is the TEE's decision to make, not the agent's.
func (a *Agent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	if a.ln != nil {
		return a.ln.Close()
	}
	return nil
}

// handle runs one tunnel end to end: handshake, allowlist, dial, pipe.
func (a *Agent) handle(conn net.Conn) {
	defer conn.Close()

	target, err := a.handshake(conn)
	if err != nil {
		// The handshake writes its own SOCKS-level refusals. Anything left is
		// a broken client; hanging up is the whole message.
		return
	}
	if !a.allows(target) {
		_ = a.reply(conn, socks5RepNotAllowed)
		return
	}

	outbound, err := a.dialTarget(target)
	if err != nil {
		_ = a.reply(conn, socks5RepRefused)
		return
	}
	defer outbound.Close()

	if err := a.reply(conn, socks5RepSucceeded); err != nil {
		return
	}
	pipe(conn, outbound)
}

// handshake negotiates the method, authenticates, and returns the CONNECT
// target as host:port.
func (a *Agent) handshake(conn net.Conn) (string, error) {
	// --- method negotiation ---
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return "", fmt.Errorf("read greeting: %w", err)
	}
	if head[0] != socks5Version {
		return "", errors.New("not a SOCKS5 client")
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", fmt.Errorf("read methods: %w", err)
	}

	var chosen byte = socks5MethodReject
	for _, method := range methods {
		if a.cfg.Auth != nil && method == socks5MethodUserPass {
			chosen = socks5MethodUserPass
			break
		}
		if a.cfg.Auth == nil && method == socks5MethodNone {
			chosen = socks5MethodNone
			break
		}
	}
	if chosen == socks5MethodReject {
		_, _ = conn.Write([]byte{socks5Version, socks5MethodReject})
		return "", errors.New("no acceptable auth method")
	}
	if _, err := conn.Write([]byte{socks5Version, chosen}); err != nil {
		return "", fmt.Errorf("send method choice: %w", err)
	}

	// --- RFC 1929 credentials ---
	if chosen == socks5MethodUserPass {
		username, password, err := readAuthMessage(conn)
		if err != nil {
			return "", err
		}
		if !a.cfg.Auth.matches(username, password) {
			// Status 0x01 then hang up. A failure reply keeps the client from
			// retrying forever against a pair it does not have.
			_, _ = conn.Write([]byte{socks5AuthVersion, 1})
			return "", errors.New("bad credentials")
		}
		if _, err := conn.Write([]byte{socks5AuthVersion, 0}); err != nil {
			return "", fmt.Errorf("send auth status: %w", err)
		}
	}

	// --- CONNECT request ---
	var request [4]byte // VER CMD RSV ATYP
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return "", fmt.Errorf("read connect request: %w", err)
	}
	if request[0] != socks5Version {
		return "", errors.New("malformed connect request")
	}
	if request[1] != socks5CmdConnect {
		// The agent is a relay, not a generic SOCKS server: BIND and UDP
		// ASSOCIATE have no meaning for a byte pipe.
		_ = a.reply(conn, socks5RepCmdUnsupported)
		return "", errors.New("unsupported command")
	}

	var host string
	switch request[3] {
	case socks5AtypIPv4:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return "", fmt.Errorf("read IPv4 target: %w", err)
		}
		host = net.IP(raw).String()
	case socks5AtypDomain:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, raw); err != nil {
			return "", fmt.Errorf("read domain target: %w", err)
		}
		host = string(raw)
	case socks5AtypIPv6:
		raw := make([]byte, 16)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return "", fmt.Errorf("read IPv6 target: %w", err)
		}
		host = net.IP(raw).String()
	default:
		_ = a.reply(conn, socks5RepAtypBad)
		return "", errors.New("unknown address type")
	}

	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return "", fmt.Errorf("read target port: %w", err)
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

// readAuthMessage reads one RFC 1929 username/password message.
func readAuthMessage(conn net.Conn) (username, password []byte, err error) {
	var version [1]byte
	if _, err = io.ReadFull(conn, version[:]); err != nil {
		return nil, nil, fmt.Errorf("read auth version: %w", err)
	}
	if version[0] != socks5AuthVersion {
		return nil, nil, errors.New("malformed auth message")
	}
	var lengths [1]byte
	if _, err = io.ReadFull(conn, lengths[:]); err != nil {
		return nil, nil, fmt.Errorf("read username length: %w", err)
	}
	username = make([]byte, int(lengths[0]))
	if _, err = io.ReadFull(conn, username); err != nil {
		return nil, nil, fmt.Errorf("read username: %w", err)
	}
	if _, err = io.ReadFull(conn, lengths[:]); err != nil {
		return nil, nil, fmt.Errorf("read password length: %w", err)
	}
	password = make([]byte, int(lengths[0]))
	if _, err = io.ReadFull(conn, password); err != nil {
		return nil, nil, fmt.Errorf("read password: %w", err)
	}
	return username, password, nil
}

// allows reports whether target is on the allowlist. Exact host:port match
// only: patterns would invite "close enough" targets that were never meant to
// be allowed.
func (a *Agent) allows(target string) bool {
	for _, allowed := range a.cfg.AllowedTargets {
		if target == allowed {
			return true
		}
	}
	return false
}

// dialTarget opens the outbound connection to the provider.
func (a *Agent) dialTarget(target string) (net.Conn, error) {
	dial := a.cfg.DialTarget
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.ConnectTimeout)
	defer cancel()
	conn, err := dial(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("dial target %s: %w", target, err)
	}
	return conn, nil
}

// reply sends one SOCKS5 reply. The bound address is zeroed: the client
// (our transport's dialer) discards it anyway.
func (a *Agent) reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{socks5Version, code, 0, socks5AtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// pipe copies bytes in both directions until either side closes. The first
// direction to finish closes both ends, which unblocks the other goroutine:
// a half-open pipe would otherwise pin a transcript relay forever.
func pipe(client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(upstream, client)
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = upstream.Close()
}

// constantTimeEqual compares two byte slices without leaking where they
// differ. Length is not secret here; contents are.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

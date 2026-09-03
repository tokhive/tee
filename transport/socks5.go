package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS5 protocol constants (RFC 1928, RFC 1929), client side. The Provider
// Agent implements the server side in the provider package; the two halves
// each own their copy of these values deliberately, so neither package needs
// to import the other for four byte literals.
const (
	socks5Version        = 5
	socks5MethodNone     = 0x00
	socks5MethodUserPass = 0x02
	socks5AuthVersion    = 1

	socks5CmdConnect = 0x01

	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04
)

// SOCKS5 dial errors. They describe the agent's side of the handshake: the
// TCP connection to the agent itself succeeded, but the agent declined.
var (
	ErrSOCKS5MethodRejected = errors.New("provider agent rejected all offered auth methods")
	ErrSOCKS5AuthFailed     = errors.New("provider agent rejected the credentials")
	ErrSOCKS5ConnectRefused = errors.New("provider agent could not reach the target")
)

// SOCKS5Auth is the username/password pair the agent validates (RFC 1929).
//
// These credentials authenticate the TEE to the agent — the opposite
// direction from the provider credential the TEE injects into requests. They
// exist so a running agent is not an open relay for whoever discovers it.
type SOCKS5Auth struct {
	Username string
	Password string
}

// SOCKS5Dialer returns a DialContext that tunnels TCP connections through a
// Provider Agent speaking SOCKS5.
//
// Plug it into Config.DialContext:
//
//	dial := transport.SOCKS5Dialer(agentAddr, &transport.SOCKS5Auth{...})
//	tr, _ := transport.New(transport.Config{DialContext: dial})
//
// The agent relays opaque TCP bytes. TLS for provider traffic still
// terminates inside the TEE, so the tunnel never sees a credential in the
// clear — it only carries the bytes of an already-encrypted session.
//
// A nil auth offers only the no-authentication method and fails against an
// agent that requires credentials.
func SOCKS5Dialer(agentAddr string, auth *SOCKS5Auth) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			return nil, fmt.Errorf("socks5: unsupported network %q", network)
		}
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", agentAddr)
		if err != nil {
			return nil, fmt.Errorf("dial provider agent: %w", err)
		}
		if err := socks5Connect(ctx, conn, auth, addr); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

// socks5Connect runs the client half of the SOCKS5 handshake and leaves conn
// as a raw pipe to target.
func socks5Connect(ctx context.Context, conn net.Conn, auth *SOCKS5Auth, target string) error {
	// Bound the handshake by the caller's deadline, if any. Afterwards the
	// connection belongs to the HTTP layer: a stream may legitimately run for
	// minutes, so no deadline may survive the handshake.
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("socks5: set deadline: %w", err)
		}
	}
	// A cancellation without a deadline must still abort a handshake blocked on
	// a silent agent: poking the deadline turns the agent's silence into a
	// timeout error. The poke is stopped before the deadline is lifted, so a
	// poke that fired at the worst moment cannot leave a stale deadline on a
	// healthy tunnel.
	stopOnCancel := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer func() {
		stopOnCancel()
		_ = conn.SetDeadline(time.Time{})
	}()

	if auth != nil {
		if len(auth.Username) > 255 || len(auth.Password) > 255 {
			return errors.New("socks5: username or password exceeds 255 bytes")
		}
	}

	// Method negotiation. Offering no-auth as a fallback lets the same dialer
	// talk to an agent that has authentication disabled (a local demo) while
	// preferring the authenticated method when both sides support it.
	methods := []byte{socks5MethodNone}
	if auth != nil {
		methods = []byte{socks5MethodUserPass, socks5MethodNone}
	}
	greeting := append([]byte{socks5Version, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("socks5: send greeting: %w", err)
	}

	var choice [2]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		return fmt.Errorf("socks5: read method choice: %w", err)
	}
	if choice[0] != socks5Version {
		return errors.New("socks5: agent is not a SOCKS5 server")
	}
	switch choice[1] {
	case socks5MethodUserPass:
		if auth == nil {
			return fmt.Errorf("%w: agent demanded credentials", ErrSOCKS5MethodRejected)
		}
		if err := socks5Authenticate(conn, auth); err != nil {
			return err
		}
	case socks5MethodNone:
		// Nothing to negotiate.
	default:
		return ErrSOCKS5MethodRejected
	}

	request, err := socks5ConnectRequest(target)
	if err != nil {
		return err
	}
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("socks5: send connect request: %w", err)
	}

	// Reply: VER REP RSV ATYP BND.ADDR BND.PORT. The bound address is
	// informational; it is read and discarded so the pipe starts at a clean
	// message boundary.
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("socks5: read reply: %w", err)
	}
	if head[0] != socks5Version {
		return errors.New("socks5: malformed agent reply")
	}
	if head[1] != 0 {
		return fmt.Errorf("%w: reply code %d", ErrSOCKS5ConnectRefused, head[1])
	}
	switch head[3] {
	case socks5AtypIPv4:
		_, err = io.CopyN(io.Discard, conn, 4+2)
	case socks5AtypDomain:
		var length [1]byte
		if _, err = io.ReadFull(conn, length[:]); err == nil {
			_, err = io.CopyN(io.Discard, conn, int64(length[0])+2)
		}
	case socks5AtypIPv6:
		_, err = io.CopyN(io.Discard, conn, 16+2)
	default:
		err = errors.New("socks5: agent reply has an unknown address type")
	}
	if err != nil {
		return fmt.Errorf("socks5: read bound address: %w", err)
	}
	return nil
}

// socks5Authenticate performs the RFC 1929 username/password exchange.
func socks5Authenticate(conn net.Conn, auth *SOCKS5Auth) error {
	request := []byte{socks5AuthVersion, byte(len(auth.Username))}
	request = append(request, auth.Username...)
	request = append(request, byte(len(auth.Password)))
	request = append(request, auth.Password...)
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("socks5: send credentials: %w", err)
	}

	var status [2]byte
	if _, err := io.ReadFull(conn, status[:]); err != nil {
		return fmt.Errorf("socks5: read auth status: %w", err)
	}
	if status[0] != socks5AuthVersion {
		return errors.New("socks5: malformed auth reply")
	}
	if status[1] != 0 {
		return ErrSOCKS5AuthFailed
	}
	return nil
}

// socks5ConnectRequest encodes a CONNECT request for target (host:port).
// IPv4, IPv6, and domain targets use their natural address types.
func socks5ConnectRequest(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("socks5: split target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("socks5: invalid port in %q", target)
	}

	request := []byte{socks5Version, socks5CmdConnect, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			request = append(request, socks5AtypIPv4)
			request = append(request, v4...)
		} else {
			request = append(request, socks5AtypIPv6)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("socks5: target host %q is empty or too long", host)
		}
		request = append(request, socks5AtypDomain, byte(len(host)))
		request = append(request, host...)
	}
	return binary.BigEndian.AppendUint16(request, uint16(port)), nil
}

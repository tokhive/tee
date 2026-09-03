package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/transport"
)

// startAgent brings up an agent on an ephemeral loopback port and returns its
// address. The agent is closed with the test.
func startAgent(t *testing.T, cfg AgentConfig) string {
	t.Helper()
	agent, err := NewAgent(cfg)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = agent.Serve(ln) }()
	t.Cleanup(func() { _ = agent.Close() })
	return ln.Addr().String()
}

// tunneledTransport builds a ChannelManager whose connections run through the
// agent at agentAddr. Provider "tunnel" is the registry key that routes through
// this agent, so every Do below sets Request.Provider to it.
func tunneledTransport(t *testing.T, agentAddr string, auth *transport.SOCKS5Auth) *transport.ChannelManager {
	t.Helper()
	ep := transport.Endpoint{AgentAddr: agentAddr}
	if auth != nil {
		ep.Username = auth.Username
		ep.Password = auth.Password
	}
	reg := transport.NewRegistry()
	reg.Set("tunnel", ep)
	cm, err := transport.NewChannelManager(transport.ChannelConfig{
		Scheme:         "http",
		AllowPlaintext: true,
		Endpoints:      reg,
	})
	if err != nil {
		t.Fatalf("NewChannelManager: %v", err)
	}
	t.Cleanup(func() { _ = cm.Close() })
	return cm
}

func TestAgentRelaysSSEStream(t *testing.T) {
	events := []string{"data: event-0\n\n", "data: event-1\n\n", "data: event-2\n\n"}
	var gotAuth capturedHeader
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Set(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, event := range events {
			fmt.Fprint(w, event)
			flusher.Flush()
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://")

	agentAddr := startAgent(t, AgentConfig{AllowedTargets: []string{target}})
	tr := tunneledTransport(t, agentAddr, nil)

	var chunks []string
	resp, err := tr.Do(context.Background(),
		tee.Request{
			Method:   "POST",
			Provider: "tunnel",
			Host:     target,
			Path:     "/v1/chat/completions",
			Headers:  map[string]string{"Authorization": "Bearer shared-credential"},
			Body:     []byte(`{"stream":true}`),
		},
		func(chunk []byte) error {
			chunks = append(chunks, string(chunk))
			return nil
		})
	if err != nil {
		t.Fatalf("Do through agent: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if gotAuth.Get() != "Bearer shared-credential" {
		t.Errorf("Authorization = %q, want the injected credential", gotAuth.Get())
	}
	if len(chunks) < 2 {
		t.Errorf("got %d chunks, want the stream relayed as it arrives (>= 2)", len(chunks))
	}
	if joined := strings.Join(chunks, ""); joined != strings.Join(events, "") {
		t.Errorf("relayed body = %q, want %q", joined, strings.Join(events, ""))
	}
}

func TestAgentRefusesTargetOutsideAllowlist(t *testing.T) {
	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer allowed.Close()
	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("agent relayed to a target outside its allowlist")
		w.WriteHeader(http.StatusOK)
	}))
	defer forbidden.Close()

	agentAddr := startAgent(t, AgentConfig{
		AllowedTargets: []string{strings.TrimPrefix(allowed.URL, "http://")},
	})
	tr := tunneledTransport(t, agentAddr, nil)

	_, err := tr.Do(context.Background(),
		tee.Request{
			Method:   "GET",
			Provider: "tunnel",
			Host:     strings.TrimPrefix(forbidden.URL, "http://"),
			Path:     "/v1/models",
		},
		func([]byte) error { return nil })
	if !errors.Is(err, transport.ErrSOCKS5ConnectRefused) {
		t.Fatalf("error = %v, want ErrSOCKS5ConnectRefused", err)
	}
}

func TestAgentAuthenticates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://")

	agentAddr := startAgent(t, AgentConfig{
		Auth:           &Auth{Username: "tee-node-1", Password: "correct-horse"},
		AllowedTargets: []string{target},
	})

	t.Run("correct credentials pass", func(t *testing.T) {
		tr := tunneledTransport(t, agentAddr, &transport.SOCKS5Auth{Username: "tee-node-1", Password: "correct-horse"})
		_, err := tr.Do(context.Background(),
			tee.Request{Method: "GET", Provider: "tunnel", Host: target, Path: "/v1/models"},
			func([]byte) error { return nil })
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
	})

	t.Run("wrong password is refused", func(t *testing.T) {
		tr := tunneledTransport(t, agentAddr, &transport.SOCKS5Auth{Username: "tee-node-1", Password: "battery"})
		_, err := tr.Do(context.Background(),
			tee.Request{Method: "GET", Provider: "tunnel", Host: target, Path: "/v1/models"},
			func([]byte) error { return nil })
		if !errors.Is(err, transport.ErrSOCKS5AuthFailed) {
			t.Fatalf("error = %v, want ErrSOCKS5AuthFailed", err)
		}
	})

	t.Run("no credentials are refused", func(t *testing.T) {
		tr := tunneledTransport(t, agentAddr, nil)
		_, err := tr.Do(context.Background(),
			tee.Request{Method: "GET", Provider: "tunnel", Host: target, Path: "/v1/models"},
			func([]byte) error { return nil })
		if !errors.Is(err, transport.ErrSOCKS5MethodRejected) {
			t.Fatalf("error = %v, want ErrSOCKS5MethodRejected", err)
		}
	})
}

func TestAgentRefusesNonConnectCommands(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://")

	agentAddr := startAgent(t, AgentConfig{AllowedTargets: []string{target}})

	conn, err := net.Dial("tcp", agentAddr)
	if err != nil {
		t.Fatalf("dial agent: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Greeting: no-auth.
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	var choice [2]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		t.Fatalf("read choice: %v", err)
	}
	if choice[0] != 5 || choice[1] != 0 {
		t.Fatalf("method choice = %v, want [5 0]", choice)
	}

	// BIND (0x02) instead of CONNECT.
	request := []byte{5, 0x02, 0, 1, 127, 0, 0, 1, 0x1f, 0x90}
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("write bind request: %v", err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != socks5RepCmdUnsupported {
		t.Errorf("reply code = %d, want %d (command not supported)", reply[1], socks5RepCmdUnsupported)
	}
}

func TestAgentRequiresAllowlist(t *testing.T) {
	if _, err := NewAgent(AgentConfig{}); !errors.Is(err, ErrEmptyAllowlist) {
		t.Fatalf("error = %v, want ErrEmptyAllowlist", err)
	}
}

// capturedHeader records one header value from the handler goroutine.
type capturedHeader struct{ v atomic.Value }

func (c *capturedHeader) Set(s string) { c.v.Store(s) }

func (c *capturedHeader) Get() string {
	loaded, _ := c.v.Load().(string)
	return loaded
}

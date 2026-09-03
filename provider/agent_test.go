package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tunnel"
)

const testAgentSecret = "s3cret-agent-key"

var testUpgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

// startEchoUpstream returns the host:port of a raw TCP server that echoes any
// bytes written to it.
func startEchoUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// miniHub plays the Hub's gate: authenticate the dial-in, receive the
// registration, then open a relay stream back toward the agent (the upstream the
// agent must dial is encoded in the registration's provider name). The relay
// stream is handed to the test so it can drive the echo directly. It exercises
// the agent's full reverse-tunnel lifecycle without depending on the rest of the
// Hub.
type miniHub struct {
	registrations chan hub.AgentRegister
	relays        chan *tunnel.Stream
	stop          chan struct{}
}

func (h *miniHub) handler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(hub.AgentKeyHeader) != testAgentSecret {
		http.Error(w, "bad key", http.StatusUnauthorized)
		return
	}
	conn, err := testUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	mux := tunnel.New(tunnel.WrapWS(conn), tunnel.Low)
	mux.Serve(func(control *tunnel.Stream, open []byte) {
		var reg hub.AgentRegister
		if err := json.Unmarshal(open, &reg); err != nil {
			_ = control.Close()
			return
		}
		h.registrations <- reg
		// Open a relay stream toward the agent naming the upstream to dial. The
		// agent bridges it; we hand the pipe to the test.
		meta, _ := json.Marshal(hub.UpstreamOpen{Host: echoHostFor(reg.Provider)})
		relay, err := mux.Dial(meta)
		if err != nil {
			return
		}
		// Drain the control stream so it stays open (the agent's lease).
		go func() { _, _ = io.Copy(io.Discard, control) }()
		h.relays <- relay
	})
	// Keep the tunnel alive for the test's lifetime: block the handler instead of
	// letting it return (which would close the connection out from under the
	// agent's registration).
	<-h.stop
	_ = mux.Close()
	_ = conn.Close()
}

func startMiniHub(t *testing.T) (*miniHub, string) {
	t.Helper()
	mh := &miniHub{
		registrations: make(chan hub.AgentRegister, 4),
		relays:        make(chan *tunnel.Stream, 4),
		stop:          make(chan struct{}),
	}
	srv := httptest.NewServer(http.HandlerFunc(mh.handler))
	t.Cleanup(func() {
		close(mh.stop)
		srv.Close()
	})
	return mh, "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/agent"
}

// echoHostFor recovers the upstream host the agent must reach from the provider
// name the miniHub chose for it. The tests name providers as their echo target,
// which keeps the relay open's meta self-consistent with the allowlist.
func echoHostFor(provider string) string {
	if i := strings.Index(provider, ":"); i >= 0 {
		return provider
	}
	return ""
}

func TestAgentRegistersAndRelays(t *testing.T) {
	echo := startEchoUpstream(t)
	mh, gateURL := startMiniHub(t)

	selfPrice := &hub.RateCard{PerRequestMicros: 250_000}
	a, err := NewAgent(AgentConfig{
		HubGateURL:     gateURL,
		SharedKey:      []byte(testAgentSecret),
		Self:           hub.AgentRegister{Provider: echo, DisplayName: "home-1", SelfPrice: selfPrice},
		AllowedTargets: []string{echo},
		ReconnectDelay: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	var reg hub.AgentRegister
	select {
	case reg = <-mh.registrations:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not register")
	}
	if reg.Provider != echo {
		t.Errorf("registered provider = %q, want %q", reg.Provider, echo)
	}
	if reg.SelfPrice == nil || reg.SelfPrice.PerRequestMicros != 250_000 {
		t.Errorf("registered self-price = %+v, want the declared card", reg.SelfPrice)
	}

	var relay *tunnel.Stream
	select {
	case relay = <-mh.relays:
	case <-time.After(5 * time.Second):
		t.Fatal("hub did not open a relay stream")
	}
	defer relay.Close()

	msg := []byte("the quick brown fox jumps over the lazy dog")
	go func() { _, _ = relay.Write(msg) }()
	back := make([]byte, len(msg))
	if _, err := io.ReadFull(relay, back); err != nil {
		t.Fatalf("read relay echo: %v", err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatalf("echo mismatch: %q", back)
	}
}

func TestAgentSampleOnlyMirrorsBytes(t *testing.T) {
	echo := startEchoUpstream(t)
	mh, gateURL := startMiniHub(t)

	var tap bytes.Buffer
	a, err := NewAgent(AgentConfig{
		HubGateURL:     gateURL,
		SharedKey:      []byte(testAgentSecret),
		Self:           hub.AgentRegister{Provider: echo},
		AllowedTargets: []string{echo},
		ReconnectDelay: 50 * time.Millisecond,
		Tap:            &tap,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	<-mh.registrations

	var relay *tunnel.Stream
	select {
	case relay = <-mh.relays:
	case <-time.After(5 * time.Second):
		t.Fatal("hub did not open a relay stream")
	}
	defer relay.Close()

	msg := []byte("plaintext-through-the-tap")
	go func() { _, _ = relay.Write(msg) }()
	back := make([]byte, len(msg))
	if _, err := io.ReadFull(relay, back); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if tap.Len() == 0 {
		t.Error("tap captured nothing")
	}
	if !strings.Contains(tap.String(), string(msg)) {
		t.Errorf("tap bytes %q missing the relayed bytes", tap.String())
	}
}

func TestAgentRefusesOutsideAllowlist(t *testing.T) {
	echo := startEchoUpstream(t)
	mh, gateURL := startMiniHub(t)

	// Allowlist deliberately omits echo, so the relay open must be refused.
	a, err := NewAgent(AgentConfig{
		HubGateURL:     gateURL,
		SharedKey:      []byte(testAgentSecret),
		Self:           hub.AgentRegister{Provider: echo},
		AllowedTargets: []string{"127.0.0.1:1"},
		ReconnectDelay: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	<-mh.registrations

	var relay *tunnel.Stream
	select {
	case relay = <-mh.relays:
	case <-time.After(5 * time.Second):
		t.Fatal("hub did not open a relay stream")
	}
	defer relay.Close()

	// The agent refuses to dial a host outside its allowlist and hangs up the
	// stream; the echo must never come back. A read that ends signals the
	// refusal; a read that succeeds is the failure.
	buf := make([]byte, 4)
	got := make(chan error, 1)
	go func() { _, err := relay.Read(buf); got <- err }()
	select {
	case err := <-got:
		if err == nil {
			t.Error("expected the relay to refuse the off-allowlist host, but it echoed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay stream neither echoed nor closed for an off-allowlist host")
	}
}

func TestAgentRejectsWrongKey(t *testing.T) {
	_, gateURL := startMiniHub(t)
	a, err := NewAgent(AgentConfig{
		HubGateURL:     gateURL,
		SharedKey:      []byte("wrong-key"),
		Self:           hub.AgentRegister{Provider: "p1"},
		AllowedTargets: []string{"127.0.0.1:1"},
		ReconnectDelay: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = a.Run(ctx) }()
	// Wrong key is refused at the gate; Run retries. Give it a couple attempts,
	// then cancel and confirm it unwinds cleanly.
	time.Sleep(60 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not stop after cancellation")
	}
}

func TestAgentRequiresConfig(t *testing.T) {
	if _, err := NewAgent(AgentConfig{}); err == nil {
		t.Fatal("expected an error for empty config")
	}
	if _, err := NewAgent(AgentConfig{HubGateURL: "ws://x"}); !errors.Is(err, ErrNoSharedKey) {
		t.Fatalf("error = %v, want ErrNoSharedKey", err)
	}
	if _, err := NewAgent(AgentConfig{HubGateURL: "ws://x", SharedKey: []byte("k")}); !errors.Is(err, ErrNoProvider) {
		t.Fatalf("error = %v, want ErrNoProvider", err)
	}
	if _, err := NewAgent(AgentConfig{
		HubGateURL: "ws://x", SharedKey: []byte("k"), Self: hub.AgentRegister{Provider: "p"},
	}); !errors.Is(err, ErrEmptyAllowlist) {
		t.Fatalf("error = %v, want ErrEmptyAllowlist", err)
	}
}

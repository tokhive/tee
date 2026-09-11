package hub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tunnel"
)

// These tests drive the real HTTP gate over a real WebSocket handshake. They
// cover the boundaries the wire actually enforces — key checks before the
// upgrade, the tunnel's stream-bound and single-lease rules, and the
// credential store's path rules — which the in-process listing tests cannot.

var testUpgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

// gateURL mounts one gate endpoint on a throwaway HTTP server and returns its
// ws:// URL.
func gateURL(t *testing.T, h *Hub, path string) string {
	t.Helper()
	mux := http.NewServeMux()
	if path == "/v1/agent" {
		mux.Handle(path, h.AgentGate(testUpgrader))
	} else {
		mux.Handle(path, h.TeeRelay(testUpgrader))
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http") + path
}

func dialGate(t *testing.T, url string, hdr http.Header) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	d := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
	return d.Dial(url, hdr)
}

// agentSession dials the gate and opens one control stream carrying reg.
func agentSession(t *testing.T, url string, hdr http.Header, reg AgentRegister) (*tunnel.Multiplexer, error) {
	t.Helper()
	conn, _, err := dialGate(t, url, hdr)
	if err != nil {
		return nil, err
	}
	mux := tunnel.New(tunnel.WrapWS(conn), tunnel.High)
	payload, err := json.Marshal(reg)
	if err != nil {
		mux.Close()
		return nil, err
	}
	if _, err := mux.Dial(payload); err != nil {
		mux.Close()
		return nil, err
	}
	return mux, nil
}

// waitOnline polls until the provider has a live tunnel, or gives up.
func waitOnline(t *testing.T, h *Hub, provider string) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := h.agents.conn(provider); ok {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

func agentHub(t *testing.T, cfg Config) *Hub {
	t.Helper()
	if cfg.Rates == nil {
		cfg.Rates = ratesTable(map[string]RateCard{
			"cheap": {PerRequestMicros: 100},
			"dear":  {PerRequestMicros: 900},
		})
	}
	return scriptedHub(t, cfg)
}

// TestAgentGateRejectsWrongKey pins the per-provider gate: a dial-in with any
// key but the one provisioned for the provider it names is refused before the
// upgrade, so it never reaches a tunnel.
func TestAgentGateRejectsWrongKey(t *testing.T) {
	h := agentHub(t, Config{AgentKeys: map[string][]byte{"cheap": []byte("right")}})
	url := gateURL(t, h, "/v1/agent")

	if conn, resp, err := dialGate(t, url, http.Header{AgentKeyHeader: {"wrong"}}); err == nil {
		conn.Close()
		t.Fatal("gate admitted a dial-in with the wrong key")
	} else if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %v, want 401", resp)
	}
	if conn, resp, err := dialGate(t, url, http.Header{
		AgentKeyHeader:      {"wrong"},
		AgentProviderHeader: {"cheap"},
	}); err == nil {
		conn.Close()
		t.Fatal("gate admitted a dial-in with the wrong key for the named provider")
	} else if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %v, want 401", resp)
	}
}

// TestAgentGatePerProviderKeyBindsTunnel pins the fix for impersonation: with
// per-provider keys, a key issued for one provider cannot be used to come
// online as another, so no seller can displace another's tunnel or collect the
// revenue routed to its name.
func TestAgentGatePerProviderKeyBindsTunnel(t *testing.T) {
	h := agentHub(t, Config{AgentKeys: map[string][]byte{
		"cheap": []byte("cheap-key"),
		"dear":  []byte("dear-key"),
	}})
	url := gateURL(t, h, "/v1/agent")

	// The provider header must be named and match a provisioned key.
	if conn, resp, err := dialGate(t, url, http.Header{AgentKeyHeader: {"cheap-key"}}); err == nil {
		conn.Close()
		t.Fatal("gate admitted a per-provider dial-in with no provider header")
	} else if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %v, want 401", resp)
	}
	if conn, resp, err := dialGate(t, url, http.Header{
		AgentKeyHeader:      {"dear-key"},
		AgentProviderHeader: {"cheap"},
	}); err == nil {
		conn.Close()
		t.Fatal("gate admitted dear's key under cheap's provider header")
	} else if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %v, want 401", resp)
	}

	// A key for cheap cannot register as dear on the control stream.
	mux, err := agentSession(t, url, http.Header{
		AgentKeyHeader:      {"cheap-key"},
		AgentProviderHeader: {"cheap"},
	}, AgentRegister{Provider: "dear", Credential: &tee.Envelope{}})
	if err != nil {
		t.Fatalf("dial with cheap's key: %v", err)
	}
	defer mux.Close()
	if waitOnline(t, h, "dear") {
		t.Fatal("a key issued for cheap registered as dear")
	}

	// The same key registering as itself is admitted.
	good, err := agentSession(t, url, http.Header{
		AgentKeyHeader:      {"cheap-key"},
		AgentProviderHeader: {"cheap"},
	}, AgentRegister{Provider: "cheap", Credential: &tee.Envelope{}})
	if err != nil {
		t.Fatalf("dial with cheap's own key: %v", err)
	}
	defer good.Close()
	if !waitOnline(t, h, "cheap") {
		t.Fatal("the provider's own key did not bring it online")
	}
}

// TestAgentTunnelSecondOpenIsRefusedWithoutDroppingTheLease is the regression
// for the Hub-wide crash a hostile agent could trigger: opening a second stream
// on its own tunnel must neither close the control lease twice nor displace
// the real registration. A panic here would take the whole test process down.
func TestAgentTunnelSecondOpenIsRefusedWithoutDroppingTheLease(t *testing.T) {
	h := agentHub(t, Config{AgentKeys: map[string][]byte{"cheap": []byte("k")}})
	url := gateURL(t, h, "/v1/agent")

	mux, err := agentSession(t, url, http.Header{
		AgentKeyHeader:      {"k"},
		AgentProviderHeader: {"cheap"},
	}, AgentRegister{Provider: "cheap", Credential: &tee.Envelope{}})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer mux.Close()
	if !waitOnline(t, h, "cheap") {
		t.Fatal("agent did not come online")
	}

	// A hostile agent opens a second stream, twice.
	for i := 0; i < 2; i++ {
		extra, err := mux.Dial([]byte(`{"provider":"cheap"}`))
		if err != nil {
			t.Fatalf("second dial %d: %v", i, err)
		}
		_ = extra.Close()
	}
	// Give the Hub a beat to (not) unwind anything.
	time.Sleep(50 * time.Millisecond)
	if _, ok := h.agents.conn("cheap"); !ok {
		t.Fatal("a second open displaced the real control stream")
	}
}

// TestAgentRegisterRejectsInvalidProviderName pins that a provider name is
// validated before it can reach the credential store's file path.
func TestAgentRegisterRejectsInvalidProviderName(t *testing.T) {
	h := agentHub(t, Config{AgentKeys: map[string][]byte{"cheap": []byte("k")}})
	url := gateURL(t, h, "/v1/agent")

	mux, err := agentSession(t, url, http.Header{
		AgentKeyHeader:      {"k"},
		AgentProviderHeader: {"cheap"},
	}, AgentRegister{Provider: "../escape", Credential: &tee.Envelope{}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer mux.Close()
	if waitOnline(t, h, "../escape") {
		t.Fatal("a provider name that escapes the store directory was registered")
	}
}

// TestFileCredentialStoreRejectsTraversal pins the store's own rule: provider +
// ".json" is joined onto its directory, so an unvalidated name would read,
// overwrite, or delete a file outside it.
func TestFileCredentialStoreRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	s := NewFileCredentialStore(dir)
	if err := s.Put("../escape", tee.Envelope{}); err == nil {
		t.Fatal("store accepted a name that escapes its directory")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape.json")); err == nil {
		t.Fatal("store wrote outside its directory")
	}
	if s.Delete("../escape") == nil {
		t.Fatal("store deleted a path that escapes its directory")
	}
	if _, ok := s.Get("../../etc/passwd"); ok {
		t.Fatal("store read a path that escapes its directory")
	}
	if err := s.Put("ok-name", tee.Envelope{KeyID: []byte("x")}); err != nil {
		t.Fatalf("store refused a valid provider name: %v", err)
	}
	if _, ok := s.Get("ok-name"); !ok {
		t.Fatal("store lost a valid envelope")
	}
}

// TestTeeRelayRequiresConfiguredKey pins the relay gate: the endpoint is an
// egress path through every online agent's tunnel, so a configured key must be
// presented.
func TestTeeRelayRequiresConfiguredKey(t *testing.T) {
	h := agentHub(t, Config{RelaySecret: []byte("relay-key")})
	url := gateURL(t, h, "/v1/relay")

	if conn, resp, err := dialGate(t, url, nil); err == nil {
		conn.Close()
		t.Fatal("relay admitted an unauthenticated dial-in")
	} else if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %v, want 401", resp)
	}
	conn, _, err := dialGate(t, url, http.Header{RelayKeyHeader: {"relay-key"}})
	if err != nil {
		t.Fatalf("relay refused the configured key: %v", err)
	}
	conn.Close()
}

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/provider"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// keyService is the TEE's credential plane as the Hub sees it: nothing but the
// inbox public key it publishes for agents to encrypt to. The private half — the
// only way to open an envelope — stays in keyService's inbox, where tests use it
// exactly as the TEE would: to open the envelope the Hub stored and assert on
// the plaintext that never existed in Hub memory.
type keyService struct {
	inbox *tee.InboxKey
}

func (k *keyService) CredentialKey(context.Context) (tee.InboxPublic, error) {
	return k.inbox.Public(), nil
}

// gateStack assembles a Hub with its agent gate, a real inbox key, and a real
// in-memory credential store. A provider agent dials in and registers its token.
// It returns the inbox key (the TEE's private half), the store the Hub committed
// the envelope to, and a stop function that ends the agent's connection so tests
// can observe the revocation path.
func gateStack(t *testing.T, token string) (*tee.InboxKey, *hub.MemoryCredentialStore, func()) {
	t.Helper()
	const agentSecret = "gate-secret"

	inbox, err := tee.GenerateInboxKey()
	if err != nil {
		t.Fatalf("inbox key: %v", err)
	}
	store := hub.NewMemoryCredentialStore()
	h, err := hub.New(hub.Config{
		TEE:             &hub.ScriptedTEE{Reply: func(int, jobs.Spec) (hub.Result, error) { return hub.Result{}, nil }},
		Rates:           map[string]hub.RateCard{"openai": {PerRequestMicros: 100}},
		Store:           memStore{},
		Verify:          func(proof.SignedReceipt) error { return nil },
		AgentSecret:     []byte(agentSecret),
		Credentials:     &keyService{inbox: inbox},
		CredentialStore: store,
	})
	if err != nil {
		t.Fatalf("new hub: %v", err)
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.Handle("/v1/agent", h.AgentGate(upgrader))
	mux.HandleFunc("/v1/credential-key", h.CredentialKeyHandler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	agent, err := provider.NewAgent(provider.AgentConfig{
		HubGateURL:     "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/agent",
		SharedKey:      []byte(agentSecret),
		Self:           hub.AgentRegister{Provider: "openai"},
		Credential:     tee.Secret{Token: token, Header: "authorization", Scheme: "Bearer"},
		AllowedTargets: []string{"127.0.0.1:1"},
	})
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	ctx, stop := context.WithCancel(context.Background())
	go func() { _ = agent.Run(ctx) }()

	// Wait until the gate has delivered the envelope (the agent is online only
	// after registration lands in the store).
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := store.Get("openai"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent envelope never reached the credential store")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return inbox, store, stop
}

// TestAgentGateRegistersAndRevokesCredential pins the whole token lifecycle in
// one place: the agent dials in, its sealed token lands in the Hub's credential
// store as ciphertext, and when the agent disconnects the token is revoked.
func TestAgentGateRegistersAndRevokesCredential(t *testing.T) {
	inbox, store, stop := gateStack(t, "sk-gate-secret")

	// The Hub committed the agent's envelope and the TEE can reopen it. Opening
	// the stored envelope here is exactly the decryption the real TEE performs
	// on every job — the token never lived in Hub memory.
	env, ok := store.Get("openai")
	if !ok {
		t.Fatal("token not registered")
	}
	secret, declared, err := inbox.Open(env)
	if err != nil {
		t.Fatalf("TEE cannot open the registered envelope: %v", err)
	}
	if declared != "openai" {
		t.Fatalf("envelope bound to %q, want openai", declared)
	}
	if secret.Token != "sk-gate-secret" || secret.Header != "authorization" || secret.Scheme != "Bearer" {
		t.Fatalf("stored secret = %+v, want the agent's declared token+shape", secret)
	}

	stop()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := store.Get("openai"); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent disconnect never revoked the token")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := store.Get("openai"); ok {
		t.Fatal("token still present after agent disconnect")
	}
}

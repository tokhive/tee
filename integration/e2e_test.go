package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/provider"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/transport"
)

// refuseTEE is a Hub TEE seam that refuses every job. e2eStack never routes a
// dispatch through it — it exists only to satisfy hub.New's wiring requirements.
type refuseTEE struct{}

func (refuseTEE) Execute(context.Context, jobs.Spec, []byte, func([]byte) error) (hub.Result, error) {
	return hub.Result{}, errUnwired
}
func (refuseTEE) OpenSession(context.Context, jobs.Spec) (hub.SessionConn, error) {
	return nil, errUnwired
}

var errUnwired = errors.New("hub TEE not wired for direct dispatch in this harness")

// memStore is a Hub receipt store that accepts everything and keeps nothing. It
// satisfies hub.New's Store requirement; no dispatch reaches it in e2eStack.
type memStore struct{}

func (memStore) Put(string, proof.SignedReceipt) error { return nil }

// executeEventually runs a job, retrying until it succeeds. The retry exists
// only to absorb the startup race between the reverse-tunnel agent dialing the
// Hub and the first job arriving: while no agent is registered yet, the Hub
// closes the relay stream and the job fails at the TLS handshake, consuming
// nothing. Once the agent is online the first attempt succeeds.
func executeEventually(t *testing.T, service *tee.Service, spec jobs.Spec, body []byte,
	onChunk func([]byte) error) (*tee.Result, error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last *tee.Result
	var err error
	for {
		last, err = service.Execute(context.Background(), tee.Job{Spec: spec, Body: body}, onChunk)
		if err == nil {
			return last, nil
		}
		if time.Now().After(deadline) {
			return last, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The tests in this file are the end-to-end milestone demo: every layer is the
// real implementation, including the network. The only things faked are the
// AI provider (an httptest server speaking OpenAI-style SSE) and the
// attestation epoch (a P-256 key instead of hardware evidence).
//
// The path under test, in full:
//
//	tee.Service -> transport.HTTP -> SOCKS5 dialer -> provider.Agent -> mock provider
//
// The agent exists to prove the credential survives the extra hop untouched:
// the TEE's request bytes reach the provider through a contributor's machine,
// and the receipt still describes exactly the exchange that happened.

var e2eEvents = [][]byte{
	[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n"),
	[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n"),
	[]byte("data: [DONE]\n\n"),
}

// signedPolicyFor is signedOpenAIPolicy with the host parameterised: the e2e
// path targets a local mock provider, not api.openai.com.
func signedPolicyFor(t *testing.T, key *ecdsa.PrivateKey, host string) policy.SignedPolicy {
	t.Helper()
	providerPolicy := policy.Policy{
		Version:     policy.VersionV1,
		Provider:    "openai",
		DisplayName: "E2E quota",
		Hosts:       []string{host},
		Rules: []policy.Rule{{
			Methods:     []string{"POST"},
			Path:        "/v1/chat/completions",
			AllowStream: true,
		}},
		Credential: policy.Credential{Header: "authorization", Scheme: "Bearer"},
		Limits: policy.Limits{
			MaxResponseBytes: 1 << 20,
			MaxBodyBytes:     1 << 16,
			AllowedHeaders:   []string{"content-type"},
		},
		IssuedAt:    now.Unix() - 3600,
		ExpiresAt:   now.Unix() + 3600,
		ProviderKey: publicKeyDER(t, key),
	}
	signed, err := policy.SignPolicy(providerPolicy, key)
	if err != nil {
		t.Fatalf("sign policy: %v", err)
	}
	return signed
}

// localChatCompletion is chatCompletion pointed at the mock provider's host.
func localChatCompletion(t *testing.T, host string) (jobs.Spec, []byte) {
	t.Helper()
	spec, body := chatCompletion(t)
	spec.Host = host
	return spec, body
}

// The path under test is the reverse-tunnel topology the design mandates:
// the agent lives behind a NAT, so it dials the Hub; the TEE dials the Hub's
// TeeRelay and egresses over the agent's tunnel. No component dials the agent
// directly.
//
//	tee.Service -> transport.ChannelManager -> Hub.TeeRelay
//	          -> provider.Agent (reverse tunnel) -> mock provider
//
// The agent still proves the credential survives the extra hop untouched: the
// TEE's request bytes reach the provider through a contributor's machine, and
// the receipt still describes exactly the exchange that happened.

// e2eStack assembles the full reverse-tunnel outbound path around a mock
// provider and returns a service ready to execute jobs against it.
func e2eStack(t *testing.T, target string, srv *httptest.Server) *tee.Service {
	t.Helper()
	const agentSecret = "s3cret-e2e-agent"

	// A minimal Hub exposing only the two reverse-tunnel endpoints: the
	// AgentGate the provider agent dials to come online, and the TeeRelay the
	// TEE dials to carry egress across those tunnels. Its Execute seam is never
	// reached here (the test drives tee.Service directly), so a stub that just
	// refuses is enough.
	h, err := hub.New(hub.Config{
		TEE:         refuseTEE{},
		Rates:       map[string]hub.RateCard{"openai": {PerRequestMicros: 100}},
		Store:       memStore{},
		Verify:      func(proof.SignedReceipt) error { return nil },
		AgentSecret: []byte(agentSecret),
	})
	if err != nil {
		t.Fatalf("new hub: %v", err)
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.Handle("/v1/agent", h.AgentGate(upgrader))
	mux.Handle("/v1/relay", h.TeeRelay(upgrader))
	hubsrv := httptest.NewServer(mux)
	t.Cleanup(hubsrv.Close)
	hubWS := "ws" + strings.TrimPrefix(hubsrv.URL, "http")

	// The contributor's machine: an agent that dials the Hub and relays only to
	// the mock provider.
	agent, err := provider.NewAgent(provider.AgentConfig{
		HubGateURL:     hubWS + "/v1/agent",
		SharedKey:      []byte(agentSecret),
		Self:           hub.AgentRegister{Provider: "openai"},
		AllowedTargets: []string{target},
	})
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	agentCtx, stopAgent := context.WithCancel(context.Background())
	t.Cleanup(stopAgent)
	go func() { _ = agent.Run(agentCtx) }()

	// The TEE's connection-resident data path, egressing through the Hub's
	// TeeRelay and the agent's reverse tunnel. The provider name on the job
	// ("openai") must match the registered agent's, which is how the Hub routes
	// the stream.
	outbound, err := transport.NewChannelManager(transport.ChannelConfig{
		Scheme:         "http",
		AllowPlaintext: true,
		RelayURL:       hubWS + "/v1/relay",
	})
	if err != nil {
		t.Fatalf("new transport: %v", err)
	}

	policies := policy.NewSet()
	if err := policies.Add(signedPolicyFor(t, generateKey(t), target), now); err != nil {
		t.Fatalf("install policy: %v", err)
	}
	credentials := tee.NewStaticCredentials()
	credentials.Set("openai", "sk-e2e-secret")

	service, err := tee.NewService(tee.Config{
		Policies:    policies,
		Credentials: credentials,
		Transport:   outbound,
		Signer:      proof.NewSigner(newEpoch(t)),
		Clock:       func() time.Time { return now },
		Seq:         tee.NewMemorySeqStore(),
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	_ = srv
	return service
}

// TestEndToEndSSEThroughProviderAgent runs one chat completion through every
// real layer and checks the receipt from the verifier's side: signature, spec
// hash, transcript, completion, and the absence of the credential from the
// proof.
func TestEndToEndSSEThroughProviderAgent(t *testing.T) {
	var sawAuth atomic.Value
	var sawBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("mock provider read body: %v", err)
		}
		sawAuth.Store(r.Header.Get("Authorization"))
		sawBody.Store(string(body))

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, event := range e2eEvents {
			w.Write(event)
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://")

	service := e2eStack(t, target, srv)
	spec, body := localChatCompletion(t, target)

	var relayed [][]byte
	result, err := executeEventually(t, service, spec, body, func(chunk []byte) error {
		relayed = append(relayed, append([]byte(nil), chunk...))
		return nil
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", result.StatusCode)
	}

	// The credential crossed the agent's tunnel and arrived as the policy
	// described it — the agent proved it cannot tamper with what it relays,
	// because TLS aside, this mock runs plain HTTP and would have shown any
	// tampering as-is.
	if got, _ := sawAuth.Load().(string); got != "Bearer sk-e2e-secret" {
		t.Errorf("provider saw Authorization %q", got)
	}
	if got, _ := sawBody.Load().(string); got != string(body) {
		t.Errorf("provider saw body %q, want %q", got, string(body))
	}

	// The stream was relayed as it arrived, not buffered and dumped.
	if len(relayed) < 2 {
		t.Errorf("got %d relayed chunks, want the SSE events as they arrive", len(relayed))
	}
	var transcript bytes.Buffer
	for _, chunk := range relayed {
		transcript.Write(chunk)
	}
	var want bytes.Buffer
	for _, event := range e2eEvents {
		want.Write(event)
	}
	if !bytes.Equal(transcript.Bytes(), want.Bytes()) {
		t.Errorf("relayed transcript diverges from what the provider sent")
	}

	// Verifier's side: signature first, then the hash comparisons.
	encoded, err := result.Receipt.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode receipt: %v", err)
	}
	verified, err := proof.DecodeAndVerify(encoded, proof.VerifyOptions{
		Now:              now.Add(time.Minute),
		AllowedPlatforms: []string{platform.PlatformAWSSEVSNP},
		MaxAge:           time.Hour,
	})
	if err != nil {
		t.Fatalf("verify receipt: %v", err)
	}
	if !covers(verified.Receipt, spec) {
		t.Fatal("receipt does not cover the executed spec")
	}
	if !verified.Receipt.MatchesStream(relayed) {
		t.Fatal("receipt does not cover the relayed transcript")
	}
	if verified.Receipt.Completion != proof.CompletionComplete {
		t.Fatalf("completion = %v, want complete", verified.Receipt.Completion)
	}
	if verified.Receipt.ChunkCount != uint64(len(relayed)) {
		t.Errorf("receipt chunk count = %d, relayed = %d", verified.Receipt.ChunkCount, len(relayed))
	}
	if bytes.Contains(encoded, []byte("sk-e2e-secret")) {
		t.Fatal("credential leaked into the receipt")
	}
}

// TestEndToEndMidStreamDisconnect runs the same path with a provider that
// drops the connection mid-transcript. The service must return a result (not
// an error) whose receipt attests a truncated exchange — this is the evidence
// a Hub needs in order not to charge for a response that never finished.
func TestEndToEndMidStreamDisconnect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		w.Write(e2eEvents[0])
		flusher.Flush()
		// Drop with the transcript unfinished: no further events, no clean
		// terminator, through the agent's tunnel like any real outage.
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://")

	service := e2eStack(t, target, srv)
	spec, body := localChatCompletion(t, target)

	var relayed [][]byte
	result, err := executeEventually(t, service, spec, body, func(chunk []byte) error {
		relayed = append(relayed, append([]byte(nil), chunk...))
		return nil
	})
	if err != nil {
		t.Fatalf("execute returned %v; a mid-flight failure must arrive as a result with a receipt", err)
	}
	if result.Receipt.Receipt.Completion != proof.CompletionTruncated {
		t.Fatalf("completion = %v, want truncated", result.Receipt.Receipt.Completion)
	}
	if !result.Truncated {
		t.Error("result does not report truncation")
	}
	if len(relayed) == 0 {
		t.Error("nothing was relayed before the disconnect")
	}

	// The receipt for a failed exchange is worth exactly as much as one for a
	// success — it must verify and cover the job either way.
	if err := proof.Verify(result.Receipt, proof.VerifyOptions{
		Now:    now.Add(time.Minute),
		MaxAge: time.Hour,
	}); err != nil {
		t.Fatalf("verify receipt: %v", err)
	}
	if !covers(result.Receipt.Receipt, spec) {
		t.Fatal("receipt does not cover the executed spec")
	}
	if !result.Receipt.Receipt.MatchesStream(relayed) {
		t.Fatal("receipt does not cover the partial transcript")
	}
}

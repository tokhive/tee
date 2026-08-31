package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/provider"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/transport"
)

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

// e2eStack assembles the full outbound path around a mock provider and
// returns a service ready to execute jobs against it.
func e2eStack(t *testing.T, target string, srv *httptest.Server) *tee.Service {
	t.Helper()

	// The contributor's machine: an agent that relays only to the mock
	// provider. In production the TEE would reach it over the network; here
	// the loopback plays that role.
	agent, err := provider.NewAgent(provider.AgentConfig{
		AllowedTargets: []string{target},
	})
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = agent.Serve(ln) }()
	t.Cleanup(func() { _ = agent.Close() })

	// The TEE's outbound HTTP, egressing through the agent's tunnel.
	outbound, err := transport.New(transport.Config{
		Scheme:         "http",
		AllowPlaintext: true,
		DialContext:    transport.SOCKS5Dialer(ln.Addr().String(), nil),
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
	result, err := service.Execute(context.Background(), tee.Job{Spec: spec, Body: body},
		func(chunk []byte) error {
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
	result, err := service.Execute(context.Background(), tee.Job{Spec: spec, Body: body},
		func(chunk []byte) error {
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

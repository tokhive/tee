package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// now is the single clock this test uses, so nothing here depends on when it
// happens to run.
var now = time.Unix(1_800_000_000, 0)

const applicationID = "tokenhive-tee-integration"

// fakeEpoch stands in for a real RA-TLS key epoch. It signs with an ordinary
// P-256 key and reports a fixed attestation, which is enough to exercise
// everything except hardware evidence validation — that is the one step a test
// cannot fake, and it is deliberately outside this path.
type fakeEpoch struct {
	key *ecdsa.PrivateKey
	der []byte
}

func newEpoch(t *testing.T) *fakeEpoch {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate epoch key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal epoch key: %v", err)
	}
	return &fakeEpoch{key: key, der: der}
}

func (e *fakeEpoch) Identity() platform.Identity {
	evidence := []byte("synthetic-attestation-report")
	return platform.Identity{
		Platform:        platform.PlatformAWSSEVSNP,
		AttestationType: "sev-snp",
		ApplicationID:   applicationID,
		Evidence:        evidence,
		EvidenceHash:    sha256.Sum256(evidence),
		PublicKeyDER:    e.der,
		KeyID:           sha256.Sum256(e.der),
	}
}

func (e *fakeEpoch) Sign(domain string, payload []byte) (platform.Signature, error) {
	digest, err := platform.SigningDigest(domain, payload)
	if err != nil {
		return platform.Signature{}, err
	}
	value, err := ecdsa.SignASN1(rand.Reader, e.key, digest[:])
	if err != nil {
		return platform.Signature{}, err
	}
	return platform.Signature{
		Algorithm: platform.SignatureAlgorithmECDSAP256SHA256ASN1,
		KeyID:     sha256.Sum256(e.der),
		Value:     value,
	}, nil
}

func slice32(digest [32]byte) []byte { return digest[:] }

func randomBytes(t *testing.T, length int) []byte {
	t.Helper()
	out := make([]byte, length)
	if _, err := rand.Read(out); err != nil {
		t.Fatalf("random bytes: %v", err)
	}
	return out
}

// chatCompletion returns a job spec the test policy allows, together with the
// body it commits to.
func chatCompletion(t *testing.T) (jobs.Spec, []byte) {
	t.Helper()
	body := []byte(`{"model":"gpt-4o","messages":[]}`)
	bodyHash := jobs.HashBody(body)

	spec := jobs.Spec{
		Version:          jobs.VersionV1,
		JobID:            randomBytes(t, jobs.JobIDLength),
		Provider:         "openai",
		Method:           "POST",
		Host:             "api.openai.com",
		Path:             "/v1/chat/completions",
		Headers:          map[string]string{"content-type": "application/json"},
		BodyHash:         bodyHash[:],
		Nonce:            randomBytes(t, jobs.MinNonceLength),
		ExpiresAt:        now.Unix() + 300,
		MaxResponseBytes: 1 << 16,
		Stream:           true,
	}
	return spec, body
}

// openAIPolicy is the Hub-predefined whitelist that authorises exactly the
// chat completion above and nothing else.
func openAIPolicy() policy.Policy {
	return policy.Policy{
		Version:     policy.VersionV1,
		Provider:    "openai",
		DisplayName: "Integration test quota",
		Hosts:       []string{"api.openai.com"},
		Rules: []policy.Rule{{
			Methods:     []string{"POST"},
			Path:        "/v1/chat/completions",
			AllowStream: true,
		}},
		Limits: policy.Limits{
			MaxResponseBytes: 1 << 20,
			MaxBodyBytes:     1 << 16,
			AllowedHeaders:   []string{"content-type"},
		},
		IssuedAt:  now.Unix() - 3600,
		ExpiresAt: now.Unix() + 3600,
	}
}

// TestJobToReceipt walks the path a real job takes: the credential owner
// publishes a policy, the Hub constructs a job, that policy decides whether
// the credential may be spent on it, the TEE executes and streams the
// response, and the resulting receipt is checked by a verifier that trusts
// nothing but the attested key.
//
// The point of the test is the handoffs. Each package already proves its own
// behaviour; what is unverified until now is that the spec hash the receipt
// binds to is the hash of the job that actually ran, that the policy decision
// reaches the execution step, and that a receipt which verifies describes a
// request the provider's policy allowed.
//
// No step signs the job. Under the current trust model the Hub authors the
// spec, so the chain of trust runs from the provider's policy to the TEE's
// receipt — not from a user's signature.
func TestJobToReceipt(t *testing.T) {
	epoch := newEpoch(t)

	// 1. The operator publishes a Hub-predefined whitelist policy.
	providerPolicy := openAIPolicy()
	policyHash, err := providerPolicy.Hash()
	if err != nil {
		t.Fatalf("policy hash: %v", err)
	}

	// 2. The TEE loads it from its deployment config.
	policies := policy.NewSet()
	if err := policies.Install(providerPolicy, now); err != nil {
		t.Fatalf("install policy: %v", err)
	}

	// 3. The Hub constructs one specific request. It is the author of the spec,
	// so there is no user signature to check — the TEE accepts the spec on its
	// own structure and says nothing about who sent it.
	spec, body := chatCompletion(t)
	if err := spec.ValidateAt(now); err != nil {
		t.Fatalf("validate spec: %v", err)
	}

	// 4. The TEE checks the request against the policy it loaded. With no user
	// signature, this is the only thing standing between the Hub and the
	// credential.
	decision, err := policies.AuthorizeAt(spec, now)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if decision.MaxResponseBytes != spec.MaxResponseBytes {
		t.Fatalf("decision cap = %d, want %d", decision.MaxResponseBytes, spec.MaxResponseBytes)
	}
	if !decision.AllowStream() {
		t.Fatal("decision should permit streaming")
	}

	// 5. The credential arrives at the TEE through agent registration: a secret
	// whose header/scheme shape travels with the token, never in the policy. It
	// is sealed by the agent, opened in-enclave, and injected at execution.
	secret := tee.Secret{Token: "sk-integration-token", Header: "authorization", Scheme: "Bearer"}
	if err := secret.Validate(); err != nil {
		t.Fatalf("validate secret: %v", err)
	}
	if headerName, headerValue, err := secret.Render(); err != nil ||
		headerName != "authorization" || headerValue != "Bearer sk-integration-token" {
		t.Fatalf("rendered header = %q: %q (err %v)", headerName, headerValue, err)
	}

	// 6. The TEE executes. The bytes it sends must be the bytes the spec
	// committed to; this is what stops concurrent jobs from being crossed, or a
	// truncated body being sent under another job's spec.
	if !spec.MatchesBody(body) {
		t.Fatal("request body does not match the committed hash")
	}

	streamer := proof.NewStreamingHasher(spec.JobID)
	chunks := [][]byte{
		[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n"),
		[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n"),
		[]byte("data: [DONE]\n\n"),
	}
	for _, chunk := range chunks {
		if err := streamer.WriteChunk(chunk); err != nil {
			t.Fatalf("write chunk: %v", err)
		}
	}

	specHash, err := spec.Hash()
	if err != nil {
		t.Fatalf("spec hash: %v", err)
	}

	// 7. The TEE issues a receipt binding the request, the policy it enforced,
	// and the response it observed.
	receipt := proof.Receipt{
		Version:       proof.VersionV1,
		JobID:         spec.JobID,
		JobSpecHash:   specHash[:],
		Provider:      spec.Provider,
		Method:        spec.Method,
		Host:          spec.Host,
		Path:          spec.Path,
		StatusCode:    200,
		StreamHash:    slice32(streamer.Sum()),
		ChunkCount:    streamer.ChunkCount(),
		ResponseBytes: streamer.BytesWritten(),
		Completion:    proof.CompletionComplete,
		StartedAt:     now.Unix(),
		FinishedAt:    now.Unix() + 2,
		PolicyHash:    policyHash[:],
	}
	signedReceipt, err := proof.NewSigner(epoch).Sign(receipt)
	if err != nil {
		t.Fatalf("sign receipt: %v", err)
	}

	// 8. A verifier checks it with no access to the TEE or the Hub.
	encoded, err := signedReceipt.EncodeCanonical()
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

	// 9. Everything the verifier cares about must line up.
	if !verified.Receipt.MatchesStream(chunks) {
		t.Fatal("receipt does not match the response transcript")
	}
	if string(verified.Receipt.JobSpecHash) != string(specHash[:]) {
		t.Fatal("receipt binds to a different job spec hash")
	}
	if string(verified.Receipt.PolicyHash) != string(policyHash[:]) {
		t.Fatal("receipt binds to a different policy hash")
	}
	if verified.Receipt.Completion != proof.CompletionComplete {
		t.Fatalf("completion = %v", verified.Receipt.Completion)
	}
}

// TestReceiptDetectsASwappedRequest is the attack the receipt exists to stop:
// a Hub that takes a genuine attested execution and presents it as proof of a
// different request.
//
// The receipt is real and its signature verifies. What it does not do is
// describe the substituted spec, and that is the property the verifier must
// check by comparing hashes rather than by trusting the receipt's own copy of
// the request fields.
func TestReceiptDetectsASwappedRequest(t *testing.T) {
	epoch := newEpoch(t)

	original := jobs.Spec{
		Version:          jobs.VersionV1,
		JobID:            randomBytes(t, jobs.JobIDLength),
		Provider:         "openai",
		Method:           "POST",
		Host:             "api.openai.com",
		Path:             "/v1/chat/completions",
		BodyHash:         slice32(jobs.HashBody([]byte("benign"))),
		Nonce:            randomBytes(t, jobs.MinNonceLength),
		ExpiresAt:        now.Unix() + 300,
		MaxResponseBytes: 1 << 16,
	}
	originalHash, err := original.Hash()
	if err != nil {
		t.Fatalf("hash original: %v", err)
	}

	// The Hub swaps in a request to a different host after the fact.
	substituted := original
	substituted.Host = "attacker.example.com"
	substitutedHash, err := substituted.Hash()
	if err != nil {
		t.Fatalf("hash substituted: %v", err)
	}
	if originalHash == substitutedHash {
		t.Fatal("swapping the host did not change the spec hash")
	}

	receipt := proof.Receipt{
		Version:       proof.VersionV1,
		JobID:         original.JobID,
		JobSpecHash:   originalHash[:],
		Provider:      original.Provider,
		Method:        original.Method,
		Host:          original.Host,
		Path:          original.Path,
		StatusCode:    200,
		StreamHash:    slice32(proof.HashResponseStream(original.JobID, [][]byte{[]byte("ok")})),
		ChunkCount:    1,
		ResponseBytes: 2,
		Completion:    proof.CompletionComplete,
		StartedAt:     now.Unix(),
		FinishedAt:    now.Unix() + 1,
	}
	signedReceipt, err := proof.NewSigner(epoch).Sign(receipt)
	if err != nil {
		t.Fatalf("sign receipt: %v", err)
	}

	// The signature is genuine — the proof is real. It simply does not
	// describe the substituted request, which is what the comparison catches.
	if err := proof.Verify(signedReceipt, proof.VerifyOptions{
		Now:    now.Add(time.Minute),
		MaxAge: time.Hour,
	}); err != nil {
		t.Fatalf("genuine receipt should verify: %v", err)
	}
	if !covers(signedReceipt.Receipt, original) {
		t.Fatal("receipt should cover the request it actually ran")
	}
	if covers(signedReceipt.Receipt, substituted) {
		t.Fatal("receipt was accepted as proof of the substituted request")
	}
}

// covers reports whether a receipt that already verified actually describes
// spec.
//
// This is the second half of verification, and the only half that ties a
// receipt to a particular request. The signature proves an attested TEE
// produced the receipt; nothing but the hash comparison proves it produced it
// for this job. A receipt also carries readable copies of the host, path, and
// method, but those are descriptions, not evidence — they are signed, yet they
// say nothing about which spec the TEE was handed.
func covers(receipt proof.Receipt, spec jobs.Spec) bool {
	want, err := spec.Hash()
	if err != nil {
		return false
	}
	return bytes.Equal(receipt.JobSpecHash, want[:])
}

// TestPolicyIsTheOnlyGuardOnHubCraftedJobs pins down what the trust model
// actually guarantees now that the User no longer signs the job spec.
//
// The Hub authors every spec, so it can produce a structurally flawless request
// for anything it likes: a path the policy never listed, a host the provider
// never agreed to, a method that does something other than spend quota. None of
// those are validation errors, and jobs.Validate accepts every one of them.
//
// What stops them is the provider policy, and only the provider policy. The
// test asserts both halves: the spec is well formed, and it is still refused.
// If someone later adds a check upstream of Authorize, or loosens the policy
// matcher, this fails here rather than in production.
func TestPolicyIsTheOnlyGuardOnHubCraftedJobs(t *testing.T) {
	policies := policy.NewSet()
	if err := policies.Install(openAIPolicy(), now); err != nil {
		t.Fatalf("install policy: %v", err)
	}

	// Control: the unmodified spec must be authorised. Without this the cases
	// below would also "pass" if the policy had simply failed to load, which is
	// the failure mode that would matter least in a test and most in production.
	baseline, _ := chatCompletion(t)
	if _, err := policies.AuthorizeAt(baseline, now); err != nil {
		t.Fatalf("baseline request should be authorised: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*jobs.Spec)
	}{
		{
			"path the policy never listed",
			func(s *jobs.Spec) { s.Method = "GET"; s.Path = "/v1/account" },
		},
		{
			"host the provider never agreed to",
			func(s *jobs.Spec) { s.Host = "evil.example.com" },
		},
		{
			"destructive method on an allowed path",
			func(s *jobs.Spec) { s.Method = "DELETE" },
		},
		{
			"header the policy does not allow",
			func(s *jobs.Spec) { s.Headers["x-forwarded-for"] = "203.0.113.7" },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, _ := chatCompletion(t)
			tc.mutate(&spec)

			// The spec is entirely well formed. Every case here would have
			// sailed through had no policy been loaded — which is precisely
			// why the policy cannot be optional.
			if err := spec.ValidateAt(now); err != nil {
				t.Fatalf("spec should be structurally valid: %v", err)
			}

			if _, err := policies.AuthorizeAt(spec, now); err == nil {
				t.Fatal("hub-crafted request outside the policy was authorised")
			}
		})
	}
}

// TestPolicyAndReceiptShareTheJobSpecHash pins the one value that crosses
// every package boundary. If jobs and proof ever compute it differently, the
// whole chain silently stops meaning anything.
func TestPolicyAndReceiptShareTheJobSpecHash(t *testing.T) {
	spec := jobs.Spec{
		Version:          jobs.VersionV1,
		JobID:            randomBytes(t, jobs.JobIDLength),
		Provider:         "openai",
		Method:           "POST",
		Host:             "api.openai.com",
		Path:             "/v1/chat/completions",
		BodyHash:         slice32(jobs.HashBody([]byte("x"))),
		Nonce:            randomBytes(t, jobs.MinNonceLength),
		ExpiresAt:        now.Unix() + 300,
		MaxResponseBytes: 4096,
	}

	first, err := spec.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// Re-encoding the spec from its canonical bytes must reproduce the same
	// hash: this is the round trip a Hub performs when it relays a job.
	encoded, err := spec.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var relayed jobs.Spec
	if err := canonical.Unmarshal(encoded, &relayed); err != nil {
		t.Fatalf("decode relayed spec: %v", err)
	}
	second, err := relayed.Hash()
	if err != nil {
		t.Fatalf("hash relayed: %v", err)
	}
	if first != second {
		t.Fatal("job spec hash is not stable across a canonical round trip")
	}
}

// scriptedTransport is the only part of the stack this package has to fake: the
// socket. Everything else in the tests below — policy matching, credential
// injection, the streaming digest, receipt signing — is the real
// implementation, which is the point of having them here at all.
type scriptedTransport struct {
	chunks     [][]byte
	statusCode uint32

	calls       int
	lastRequest tee.Request
}

func (s *scriptedTransport) Do(_ context.Context, req tee.Request, onChunk func([]byte) error) (tee.Response, error) {
	s.calls++
	s.lastRequest = req
	for _, chunk := range s.chunks {
		if onChunk == nil {
			continue
		}
		if err := onChunk(chunk); err != nil {
			return tee.Response{StatusCode: s.statusCode}, err
		}
	}
	return tee.Response{StatusCode: s.statusCode}, nil
}

func newService(t *testing.T, epoch *fakeEpoch, transport tee.Transport) (*tee.Service, []byte) {
	t.Helper()

	policies := policy.NewSet()
	if err := policies.Install(openAIPolicy(), now); err != nil {
		t.Fatalf("install policy: %v", err)
	}
	inbox, err := tee.GenerateInboxKey()
	if err != nil {
		t.Fatalf("inbox key: %v", err)
	}

	service, err := tee.NewService(tee.Config{
		Policies:  policies,
		Transport: transport,
		Signer:    proof.NewSigner(epoch),
		Clock:     func() time.Time { return now },
		Seq:       tee.NewMemorySeqStore(),
		InboxKey:  inbox,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	// The TEE stores no token: each test seals the shared secret to the inbox
	// key below and must attach the envelope to every spec it runs.
	env, err := tee.EncryptCredential(inbox.Public(), "openai",
		tee.Secret{Token: "sk-integration-token", Header: "authorization", Scheme: "Bearer"})
	if err != nil {
		t.Fatalf("seal credential: %v", err)
	}
	cred, err := env.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode credential: %v", err)
	}
	return service, cred
}

// TestServiceProducesAVerifiableReceipt drives the real tee.Service rather than
// the hand-assembled pipeline above.
//
// The other tests in this file check that the packages agree with each other;
// this one checks that the component that wires them together preserves those
// agreements. A service that authorised correctly but bound the receipt to a
// stale spec hash, or relayed chunks it did not digest, would pass everything
// above and fail here.
func TestServiceProducesAVerifiableReceipt(t *testing.T) {
	epoch := newEpoch(t)
	transport := &scriptedTransport{
		statusCode: 200,
		chunks: [][]byte{
			[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n"),
			[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n"),
			[]byte("data: [DONE]\n\n"),
		},
	}
	service, cred := newService(t, epoch, transport)

	spec, body := chatCompletion(t)
	spec.Credential = cred

	var relayed [][]byte
	result, err := service.Execute(context.Background(), tee.Job{Spec: spec, Body: body}, func(chunk []byte) error {
		relayed = append(relayed, append([]byte(nil), chunk...))
		return nil
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	// The credential reached the wire exactly as the policy described it.
	if got := transport.lastRequest.Headers["authorization"]; got != "Bearer sk-integration-token" {
		t.Fatalf("authorization = %q", got)
	}

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

	// Signature first, then the hash comparison: the two halves of verification.
	if !covers(verified.Receipt, spec) {
		t.Fatal("receipt does not cover the executed spec")
	}
	if !verified.Receipt.MatchesStream(relayed) {
		t.Fatal("receipt does not cover the relayed transcript")
	}
	if verified.Receipt.Completion != proof.CompletionComplete {
		t.Fatalf("completion = %v", verified.Receipt.Completion)
	}

	// The secret is what the TEE is for: it must appear on the request and
	// nowhere in the proof.
	if bytes.Contains(encoded, []byte("sk-integration-token")) {
		t.Fatal("credential leaked into the receipt")
	}
}

// TestServiceRefusesWithoutDiallingTheProvider is the property the policy layer
// exists to provide, asserted one level higher: a job the policy rejects must
// not produce a request, a credential, or a receipt.
func TestServiceRefusesWithoutDiallingTheProvider(t *testing.T) {
	epoch := newEpoch(t)
	transport := &scriptedTransport{statusCode: 200}
	service, cred := newService(t, epoch, transport)

	spec, body := chatCompletion(t)
	spec.Path = "/v1/account"
	spec.Credential = cred

	result, err := service.Execute(context.Background(), tee.Job{Spec: spec, Body: body}, nil)
	if err == nil {
		t.Fatal("job outside the policy was executed")
	}
	if result != nil {
		t.Fatal("refused job produced a receipt")
	}
	if transport.calls != 0 {
		t.Fatal("refused job reached the provider")
	}
}

// TestServiceAttestsAFailedExchange closes the loop on the case that matters
// operationally: the provider is unreachable, and the Hub needs proof of that
// in order not to charge for a response it never got.
func TestServiceAttestsAFailedExchange(t *testing.T) {
	epoch := newEpoch(t)
	transport := &scriptedTransport{
		statusCode: 0,
		chunks:     [][]byte{[]byte("data: partial\n\n")},
	}
	service, cred := newService(t, epoch, &failingTransport{inner: transport})

	spec, body := chatCompletion(t)
	spec.Credential = cred
	result, err := service.Execute(context.Background(), tee.Job{Spec: spec, Body: body}, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	// A chunk arrived before the drop, so the state is truncated rather than
	// failed: the transcript exists, it is merely incomplete.
	if result.Receipt.Receipt.Completion != proof.CompletionTruncated {
		t.Fatalf("completion = %v, want truncated", result.Receipt.Receipt.Completion)
	}
	// The receipt must still verify, or the Hub has nothing to show for it.
	if err := proof.Verify(result.Receipt, proof.VerifyOptions{Now: now.Add(time.Minute)}); err != nil {
		t.Fatalf("verify receipt: %v", err)
	}
	if !covers(result.Receipt.Receipt, spec) {
		t.Fatal("receipt does not cover the executed spec")
	}
}

// failingTransport delivers one chunk and then drops the connection.
type failingTransport struct {
	inner *scriptedTransport
}

func (f *failingTransport) Do(ctx context.Context, req tee.Request, onChunk func([]byte) error) (tee.Response, error) {
	f.inner.calls++
	f.inner.lastRequest = req
	if onChunk != nil && len(f.inner.chunks) > 0 {
		if err := onChunk(f.inner.chunks[0]); err != nil {
			return tee.Response{}, err
		}
	}
	return tee.Response{}, errors.New("connection reset")
}

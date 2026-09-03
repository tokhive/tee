package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// Fixed clock so that expiry assertions do not depend on when the test runs.
var now = time.Unix(1_800_000_000, 0)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func publicKeyDER(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return der
}

// openAIPolicy is a representative policy: chat and embeddings on one host,
// credential injected as a bearer token.
func openAIPolicy(t *testing.T, key *ecdsa.PrivateKey) Policy {
	t.Helper()
	return Policy{
		Version:     VersionV1,
		Provider:    "openai",
		DisplayName: "OpenAI shared quota",
		Hosts:       []string{"api.openai.com"},
		Rules: []Rule{
			{
				Methods:     []string{"POST"},
				Path:        "/v1/chat/completions",
				AllowStream: true,
			},
			{
				Methods: []string{"POST"},
				Path:    "/v1/embeddings",
			},
			{
				Methods:   []string{"GET"},
				Path:      "/v1/models/{model}",
				QueryKeys: []string{"include"},
			},
		},
		Credential: Credential{Header: "authorization", Scheme: "Bearer"},
		Limits: Limits{
			MaxResponseBytes: 1 << 20,
			MaxBodyBytes:     1 << 16,
			AllowedHeaders:   []string{"content-type", "openai-organization"},
		},
		IssuedAt:    now.Unix() - 3600,
		ExpiresAt:   now.Unix() + 3600,
		ProviderKey: publicKeyDER(t, key),
	}
}

func signedPolicy(t *testing.T, key *ecdsa.PrivateKey) SignedPolicy {
	t.Helper()
	signed, err := SignPolicy(openAIPolicy(t, key), key)
	if err != nil {
		t.Fatalf("sign policy: %v", err)
	}
	return signed
}

func bodyHash(body string) []byte {
	digest := jobs.HashBody([]byte(body))
	return digest[:]
}

func spec(t *testing.T, mutate func(*jobs.Spec)) jobs.Spec {
	t.Helper()
	s := jobs.Spec{
		Version:          jobs.VersionV1,
		JobID:            make([]byte, jobs.JobIDLength),
		Provider:         "openai",
		Method:           "POST",
		Host:             "api.openai.com",
		Path:             "/v1/chat/completions",
		Headers:          map[string]string{"content-type": "application/json"},
		BodyHash:         bodyHash(`{"model":"gpt-4o"}`),
		Nonce:            make([]byte, jobs.MinNonceLength),
		ExpiresAt:        now.Unix() + 60,
		MaxResponseBytes: 1 << 16,
	}
	if _, err := rand.Read(s.JobID); err != nil {
		t.Fatalf("random job ID: %v", err)
	}
	if _, err := rand.Read(s.Nonce); err != nil {
		t.Fatalf("random nonce: %v", err)
	}
	if mutate != nil {
		mutate(&s)
	}
	return s
}

func TestPolicyHashIsCanonical(t *testing.T) {
	key := testKey(t)
	policy := openAIPolicy(t, key)

	first, err := policy.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	second, err := policy.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if first != second {
		t.Fatal("policy hash is not deterministic")
	}

	// Canonical encoding must sort map-like content and never depend on Go
	// struct field order, so a reordered rule list must hash differently while
	// an identical one must not.
	reordered := policy
	reordered.Rules = []Rule{policy.Rules[2], policy.Rules[0], policy.Rules[1]}
	reorderedHash, err := reordered.Hash()
	if err != nil {
		t.Fatalf("hash reordered: %v", err)
	}
	if reorderedHash == first {
		t.Fatal("reordering rules did not change the policy hash")
	}

	tampered := policy
	tampered.Limits.MaxResponseBytes = 1 << 30
	tamperedHash, err := tampered.Hash()
	if err != nil {
		t.Fatalf("hash tampered: %v", err)
	}
	if tamperedHash == first {
		t.Fatal("changing a limit did not change the policy hash")
	}
}

func TestPolicyValidateRejectsMalformed(t *testing.T) {
	key := testKey(t)

	cases := []struct {
		name   string
		want   error
		change func(*Policy)
	}{
		{
			name:   "unsupported version",
			want:   ErrUnsupportedVersion,
			change: func(p *Policy) { p.Version = 2 },
		},
		{
			name:   "empty provider",
			want:   jobs.ErrInvalidProvider,
			change: func(p *Policy) { p.Provider = "" },
		},
		{
			name:   "uppercase provider",
			want:   jobs.ErrInvalidProvider,
			change: func(p *Policy) { p.Provider = "OpenAI" },
		},
		{
			name:   "no hosts",
			want:   ErrNoHosts,
			change: func(p *Policy) { p.Hosts = nil },
		},
		{
			name:   "host with path",
			want:   ErrInvalidHost,
			change: func(p *Policy) { p.Hosts = []string{"api.openai.com/v1"} },
		},
		{
			name:   "host with scheme",
			want:   ErrInvalidHost,
			change: func(p *Policy) { p.Hosts = []string{"https://api.openai.com"} },
		},
		{
			name:   "duplicate hosts",
			want:   ErrInvalidHost,
			change: func(p *Policy) { p.Hosts = []string{"api.openai.com", "API.openai.com"} },
		},
		{
			name:   "no rules",
			want:   ErrNoRules,
			change: func(p *Policy) { p.Rules = nil },
		},
		{
			name:   "relative path rule",
			want:   ErrInvalidPathRule,
			change: func(p *Policy) { p.Rules[0].Path = "v1/chat" },
		},
		{
			name:   "malformed placeholder",
			want:   ErrInvalidPathRule,
			change: func(p *Policy) { p.Rules[2].Path = "/v1/models/{model" },
		},
		{
			name:   "empty placeholder",
			want:   ErrInvalidPathRule,
			change: func(p *Policy) { p.Rules[2].Path = "/v1/models/{}" },
		},
		{
			name:   "unsupported method",
			want:   ErrInvalidMethods,
			change: func(p *Policy) { p.Rules[0].Methods = []string{"TRACE"} },
		},
		{
			name:   "no methods",
			want:   ErrInvalidMethods,
			change: func(p *Policy) { p.Rules[0].Methods = nil },
		},
		{
			name:   "empty credential header",
			want:   ErrInvalidCredential,
			change: func(p *Policy) { p.Credential.Header = "" },
		},
		{
			name:   "credential into host header",
			want:   ErrInvalidCredential,
			change: func(p *Policy) { p.Credential.Header = "Host" },
		},
		{
			name:   "credential into content-length",
			want:   ErrInvalidCredential,
			change: func(p *Policy) { p.Credential.Header = "content-length" },
		},
		{
			name:   "credential header with space",
			want:   ErrInvalidCredential,
			change: func(p *Policy) { p.Credential.Header = "x api key" },
		},
		{
			name:   "zero response limit",
			want:   ErrInvalidLimits,
			change: func(p *Policy) { p.Limits.MaxResponseBytes = 0 },
		},
		{
			name:   "tee-controlled header whitelisted",
			want:   ErrInvalidHeaderName,
			change: func(p *Policy) { p.Limits.AllowedHeaders = []string{"authorization"} },
		},
		{
			name:   "invalid header name whitelisted",
			want:   ErrInvalidHeaderName,
			change: func(p *Policy) { p.Limits.AllowedHeaders = []string{"content type"} },
		},
		{
			name:   "expiry before issue",
			want:   ErrInvalidTimeRange,
			change: func(p *Policy) { p.ExpiresAt = p.IssuedAt - 1 },
		},
		{
			name:   "zero issued at",
			want:   ErrInvalidTimeRange,
			change: func(p *Policy) { p.IssuedAt = 0 },
		},
		{
			name:   "signing key is not a key",
			want:   ErrInvalidSigningKey,
			change: func(p *Policy) { p.ProviderKey = []byte("not a key") },
		},
		{
			name:   "short nonce",
			want:   ErrInvalidNonce,
			change: func(p *Policy) { p.Nonce = []byte("short") },
		},
		{
			name:   "invalid query key",
			want:   ErrInvalidQueryKey,
			change: func(p *Policy) { p.Rules[2].QueryKeys = []string{"a[b]"} },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := openAIPolicy(t, key)
			tc.change(&policy)
			err := policy.Validate()
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPolicyValidateAtWindow(t *testing.T) {
	key := testKey(t)
	policy := openAIPolicy(t, key)

	if err := policy.ValidateAt(now); err != nil {
		t.Fatalf("policy should be valid now: %v", err)
	}

	before := now.Add(-24 * time.Hour)
	if err := policy.ValidateAt(before); !errors.Is(err, ErrPolicyNotYetValid) {
		t.Fatalf("before window: error = %v, want %v", err, ErrPolicyNotYetValid)
	}

	after := now.Add(24 * time.Hour)
	if err := policy.ValidateAt(after); !errors.Is(err, ErrPolicyExpired) {
		t.Fatalf("after window: error = %v, want %v", err, ErrPolicyExpired)
	}
}

// TestUnsignedPolicyIsStructurallyValid locks the deployment posture: the
// Hub-predefined whitelist is not signed by the provider, so a Policy with an
// empty ProviderKey must pass structure validation. Signatures are optional at
// this layer — they live on the SignedPolicy wrapper, which keeps the legacy
// path intact without forcing the deployment path to invent a key.
func TestUnsignedPolicyIsStructurallyValid(t *testing.T) {
	policy := openAIPolicy(t, testKey(t))
	policy.ProviderKey = nil
	if err := policy.ValidateAt(now); err != nil {
		t.Fatalf("unsigned deployment policy failed validation: %v", err)
	}
	// And its hash is stable and usable as the receipt's PolicyHash anchor.
	hash, err := policy.Hash()
	if err != nil {
		t.Fatalf("hash unsigned policy: %v", err)
	}
	if hash == [32]byte{} {
		t.Fatal("unsigned policy hashed to zero")
	}
}

func TestSignAndVerifyPolicy(t *testing.T) {
	key := testKey(t)
	signed := signedPolicy(t, key)

	if err := VerifySignedPolicy(signed, now); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// A policy is self-certifying: the embedded key must be the signing key,
	// so swapping in another provider's key must break verification.
	forged := signed
	forged.Policy.ProviderKey = publicKeyDER(t, testKey(t))
	if err := VerifySignedPolicy(forged, now); err == nil {
		t.Fatal("policy signed by a different key than it names was accepted")
	}

	// Signatures must cover every policy field. Widen the limit and the
	// signature from the original policy must stop verifying.
	tampered := signed
	tampered.Policy.Limits.MaxResponseBytes = 1 << 40
	if err := VerifySignedPolicy(tampered, now); err == nil {
		t.Fatal("tampered policy still verified")
	}

	// Adding a rule is the most dangerous tamper: it grants new access.
	widened := signed
	widened.Policy.Rules = append(widened.Policy.Rules, Rule{
		Methods: []string{"POST"},
		Path:    "/v1/anything",
	})
	if err := VerifySignedPolicy(widened, now); err == nil {
		t.Fatal("policy with an added rule still verified")
	}
}

func TestSignPolicyOverwritesProviderKey(t *testing.T) {
	key := testKey(t)
	policy := openAIPolicy(t, key)

	// Claim a foreign key before signing; SignPolicy must replace it.
	policy.ProviderKey = publicKeyDER(t, testKey(t))
	signed, err := SignPolicy(policy, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	want := publicKeyDER(t, key)
	if !strings.EqualFold(string(signed.Policy.ProviderKey), string(want)) {
		t.Fatal("SignPolicy did not overwrite the claimed provider key")
	}
	if err := VerifySignedPolicy(signed, now); err != nil {
		t.Fatalf("verify after overwrite: %v", err)
	}
}

func TestSignPolicyRejectsBadKey(t *testing.T) {
	key := testKey(t)
	policy := openAIPolicy(t, key)

	if _, err := SignPolicy(policy, nil); !errors.Is(err, ErrInvalidProviderKey) {
		t.Fatalf("nil key: error = %v, want %v", err, ErrInvalidProviderKey)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	if _, err := SignPolicy(policy, p384); !errors.Is(err, ErrInvalidProviderKey) {
		t.Fatalf("P-384 key: error = %v, want %v", err, ErrInvalidProviderKey)
	}
}

func TestVerifySignedPolicyAcceptsZeroTime(t *testing.T) {
	key := testKey(t)
	signed := signedPolicy(t, key)

	// Archived policies are verified against their own epoch, not against now.
	if err := VerifySignedPolicy(signed, time.Time{}); err != nil {
		t.Fatalf("zero time should skip the window check: %v", err)
	}
}

func TestDecodeSignedPolicyRejectsNonCanonical(t *testing.T) {
	key := testKey(t)
	signed := signedPolicy(t, key)

	encoded, err := signed.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := DecodeSignedPolicy(encoded); err != nil {
		t.Fatalf("decode canonical: %v", err)
	}

	// An indefinite-length map carries the same content in different bytes.
	// Accepting it would let one policy hash two ways.
	indefinite := append([]byte{0xbf}, encoded[1:]...)
	if _, err := DecodeSignedPolicy(indefinite); err == nil {
		t.Fatal("indefinite-length encoding was accepted")
	}
	if _, err := DecodeSignedPolicy([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("garbage bytes were accepted")
	}
	// canonical is still imported for the round-trip assertion above.
	_ = canonical.ErrNonCanonical
}

func TestAuthorizeAllowsMatchingJob(t *testing.T) {
	key := testKey(t)
	policy := openAIPolicy(t, key)

	decision, err := policy.Authorize(spec(t, nil))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if decision.Provider != "openai" {
		t.Fatalf("provider = %q, want openai", decision.Provider)
	}
	if decision.MaxResponseBytes != 1<<16 {
		t.Fatalf("MaxResponseBytes = %d, want the job's own %d", decision.MaxResponseBytes, 1<<16)
	}
	if decision.MaxBodyBytes != 1<<16 {
		t.Fatalf("MaxBodyBytes = %d, want %d", decision.MaxBodyBytes, 1<<16)
	}
	if !decision.AllowStream() {
		t.Fatal("streaming should be allowed on /v1/chat/completions")
	}
}

func TestAuthorizeRejectsBypasses(t *testing.T) {
	key := testKey(t)
	policy := openAIPolicy(t, key)

	cases := []struct {
		name   string
		want   error
		change func(*jobs.Spec)
	}{
		{
			name: "provider mismatch",
			want: ErrProviderMismatch,
			change: func(s *jobs.Spec) {
				s.Provider = "anthropic"
			},
		},
		{
			name: "host not in policy",
			want: ErrHostNotAllowed,
			change: func(s *jobs.Spec) {
				s.Host = "evil.example.com"
			},
		},
		{
			name: "host suffix confusion",
			want: ErrHostNotAllowed,
			change: func(s *jobs.Spec) {
				s.Host = "api.openai.com.evil.example.com"
			},
		},
		{
			name: "host prefix confusion",
			want: ErrHostNotAllowed,
			change: func(s *jobs.Spec) {
				s.Host = "notapi.openai.com"
			},
		},
		{
			name: "non-default port",
			want: ErrHostNotAllowed,
			change: func(s *jobs.Spec) {
				s.Host = "api.openai.com:8443"
			},
		},
		{
			name: "path outside policy",
			want: ErrPathNotAllowed,
			change: func(s *jobs.Spec) {
				s.Path = "/v1/admin/keys"
			},
		},
		{
			name: "sibling path is not covered by prefix",
			want: ErrPathNotAllowed,
			change: func(s *jobs.Spec) {
				s.Path = "/v1/chat/completions-backdoor"
			},
		},
		{
			name: "method not allowed on a known path",
			want: ErrMethodNotAllowed,
			change: func(s *jobs.Spec) {
				s.Method = "DELETE"
			},
		},
		{
			name: "streaming where the rule forbids it",
			want: ErrStreamNotAllowed,
			change: func(s *jobs.Spec) {
				s.Path = "/v1/embeddings"
				s.Stream = true
			},
		},
		{
			name: "header outside the whitelist",
			want: ErrHeaderNotAllowed,
			change: func(s *jobs.Spec) {
				s.Headers["x-evil"] = "1"
			},
		},
		{
			name: "query outside the whitelist",
			want: ErrQueryNotAllowed,
			change: func(s *jobs.Spec) {
				s.Method = "GET"
				s.Path = "/v1/models/gpt-4o"
				s.Query = "secret=1"
			},
		},
		{
			name: "job asks for more bytes than the policy allows",
			want: ErrLimitExceeded,
			change: func(s *jobs.Spec) {
				s.MaxResponseBytes = 1 << 40
			},
		},
		{
			name: "job itself is malformed",
			want: jobs.ErrInvalidPath,
			change: func(s *jobs.Spec) {
				s.Path = "/v1/../admin"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := spec(t, tc.change)
			_, err := policy.Authorize(job)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Authorize() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAuthorizeAtEnforcesBothWindows(t *testing.T) {
	key := testKey(t)
	policy := openAIPolicy(t, key)

	if _, err := policy.AuthorizeAt(spec(t, nil), now); err != nil {
		t.Fatalf("authorize at now: %v", err)
	}

	expiredJob := spec(t, func(s *jobs.Spec) { s.ExpiresAt = now.Unix() - 1 })
	if _, err := policy.AuthorizeAt(expiredJob, now); !errors.Is(err, jobs.ErrExpired) {
		t.Fatalf("expired job: error = %v, want %v", err, jobs.ErrExpired)
	}

	after := now.Add(24 * time.Hour)
	if _, err := policy.AuthorizeAt(spec(t, nil), after); !errors.Is(err, ErrPolicyExpired) {
		t.Fatalf("expired policy: error = %v, want %v", err, ErrPolicyExpired)
	}
}

func TestMatchPathRule(t *testing.T) {
	cases := []struct {
		rule     string
		request  string
		expected bool
	}{
		{"/v1/chat/completions", "/v1/chat/completions", true},
		{"/v1/chat/completions", "/v1/chat/completions/", false}, // trailing slash is a different resource
		{"/v1/chat", "/v1/chat/completions", true},               // prefix on a segment boundary
		{"/v1/chat", "/v1/chat-backdoor", false},                 // prefix without a boundary must not match
		{"/v1", "/v1", true},
		{"/v1", "/v11", false},
		{"/", "/", true},
		{"/", "/v1", false},
		{"/v1/models/{model}", "/v1/models/gpt-4o", true},
		{"/v1/models/{model}", "/v1/models/gpt-4o/capabilities", true},
		{"/v1/models/{model}", "/v1/models", false},
		{"/v1/models/{model}", "/v1/models/", false},
		{"/v1/{a}/{b}", "/v1/x/y", true},
		{"/v1/{a}/{b}", "/v1/x", false},
	}

	for _, tc := range cases {
		if got := matchPathRule(tc.rule, tc.request); got != tc.expected {
			t.Errorf("matchPathRule(%q, %q) = %v, want %v", tc.rule, tc.request, got, tc.expected)
		}
	}
}

func TestHostMatches(t *testing.T) {
	cases := []struct {
		allowed  string
		request  string
		expected bool
	}{
		{"api.openai.com", "api.openai.com", true},
		{"api.openai.com", "API.OPENAI.COM", true},
		{"api.openai.com", "api.openai.com:443", true},
		{"api.openai.com:443", "api.openai.com", true},
		{"api.openai.com", "api.openai.com:8443", false},
		{"api.openai.com", "api.openai.com.evil.com", false},
		{"api.openai.com", "evil.com", false},
	}

	for _, tc := range cases {
		if got := hostMatches(tc.allowed, tc.request); got != tc.expected {
			t.Errorf("hostMatches(%q, %q) = %v, want %v", tc.allowed, tc.request, got, tc.expected)
		}
	}
}

func TestCredentialInject(t *testing.T) {
	credential := Credential{Header: "authorization", Scheme: "Bearer"}

	name, value, err := credential.Inject("sk-test")
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if name != "authorization" || value != "Bearer sk-test" {
		t.Fatalf("inject = (%q, %q), want (%q, %q)", name, value, "authorization", "Bearer sk-test")
	}

	// A raw API key header has no scheme.
	raw := Credential{Header: "api-key"}
	if _, value, err = raw.Inject("secret"); err != nil || value != "secret" {
		t.Fatalf("raw inject = %q, err = %v", value, err)
	}

	// Header injection through the credential is the real risk: the secret is
	// the one value the TEE must never let escape into a second header line.
	for _, bad := range []string{"", "sk-\r\nx-evil: 1", "sk-\n", "sk-\x00", " sk-test "} {
		if _, _, err := credential.Inject(bad); err == nil {
			t.Errorf("Inject(%q) accepted an unsafe credential", bad)
		}
	}
}

func TestPolicySetAddAndAuthorize(t *testing.T) {
	key := testKey(t)
	set := NewSet()

	if err := set.Add(signedPolicy(t, key), now); err != nil {
		t.Fatalf("add: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", set.Len())
	}
	if providers := set.Providers(); len(providers) != 1 || providers[0] != "openai" {
		t.Fatalf("Providers() = %v, want [openai]", providers)
	}

	decision, err := set.Authorize(spec(t, nil))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if decision.Provider != "openai" {
		t.Fatalf("provider = %q", decision.Provider)
	}

	unknown := spec(t, func(s *jobs.Spec) { s.Provider = "anthropic" })
	if _, err := set.Authorize(unknown); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("unknown provider: error = %v, want %v", err, ErrUnknownProvider)
	}

	set.Remove("openai")
	if _, err := set.Authorize(spec(t, nil)); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("after remove: error = %v, want %v", err, ErrUnknownProvider)
	}
}

func TestPolicySetRejectsUnsignedAndStale(t *testing.T) {
	key := testKey(t)
	other := testKey(t)
	set := NewSet()

	if err := set.Add(signedPolicy(t, key), now); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Forged: signed by a key other than the one the policy names.
	forged := signedPolicy(t, key)
	forged.Signature.KeyID = sha256.Sum256(publicKeyDER(t, other))
	if err := set.Add(forged, now); err == nil {
		t.Fatal("set accepted a policy with a mismatched signature key")
	}

	// Expired: valid once, not now.
	expired := openAIPolicy(t, key)
	expired.IssuedAt = now.Unix() - 7200
	expired.ExpiresAt = now.Unix() - 3600
	expiredSigned, err := SignPolicy(expired, key)
	if err != nil {
		t.Fatalf("sign expired: %v", err)
	}
	if err := set.Add(expiredSigned, now); !errors.Is(err, ErrPolicyExpired) {
		t.Fatalf("expired policy: error = %v, want %v", err, ErrPolicyExpired)
	}

	// Rollback: an older policy must not replace a newer one.
	newer := openAIPolicy(t, key)
	newer.IssuedAt = now.Unix()
	newerSigned, err := SignPolicy(newer, key)
	if err != nil {
		t.Fatalf("sign newer: %v", err)
	}
	if err := set.Add(newerSigned, now); err != nil {
		t.Fatalf("add newer: %v", err)
	}
	if err := set.Add(signedPolicy(t, key), now); !errors.Is(err, ErrPolicyRollback) {
		t.Fatalf("rollback: error = %v, want %v", err, ErrPolicyRollback)
	}
}

func TestPolicySetLoadIsAtomic(t *testing.T) {
	key := testKey(t)
	other := testKey(t)
	set := NewSet()

	good := signedPolicy(t, key)
	bad := signedPolicy(t, other)
	// Make the second entry structurally invalid after signing so that Load
	// fails partway through and must install nothing.
	bad.Policy.Limits.MaxResponseBytes = 0

	before := set.Len()
	if err := set.Load([]SignedPolicy{good, bad}, now); err == nil {
		t.Fatal("Load accepted an invalid entry")
	}
	if set.Len() != before {
		t.Fatalf("Load partially applied: Len() = %d, want %d", set.Len(), before)
	}

	if err := set.Load([]SignedPolicy{good}, now); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", set.Len())
	}
}

func TestPolicySetInstallUnsignedDeploymentPolicy(t *testing.T) {
	set := NewSet()

	// The deployment path: a Hub-predefined whitelist with no provider key.
	unsigned := openAIPolicy(t, testKey(t))
	unsigned.ProviderKey = nil
	if err := set.Install(unsigned, now); err != nil {
		t.Fatalf("install unsigned policy: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", set.Len())
	}

	decision, err := set.Authorize(spec(t, nil))
	if err != nil {
		t.Fatalf("authorize deployment-installed policy: %v", err)
	}
	if decision.Provider != "openai" {
		t.Fatalf("provider = %q, want openai", decision.Provider)
	}
	// The PolicyHash anchor still works — the receipt binds to the policy hash,
	// which is independent of whether a signature wrapper was ever present.
	got, _ := set.Get("openai")
	if got.Provider != "openai" {
		t.Fatalf("Get() provider = %q", got.Provider)
	}
}

func TestPolicySetInstallAllIsAtomic(t *testing.T) {
	set := NewSet()
	good := openAIPolicy(t, testKey(t))
	good.ProviderKey = nil

	// Structurally invalid after the fact, so InstallAll must fail partway and
	// install nothing.
	bad := openAIPolicy(t, testKey(t))
	bad.Provider = "anthropic"
	bad.Limits.MaxResponseBytes = 0

	before := set.Len()
	if err := set.InstallAll([]Policy{good, bad}, now); err == nil {
		t.Fatal("InstallAll accepted an invalid entry")
	}
	if set.Len() != before {
		t.Fatalf("InstallAll partially applied: Len() = %d, want %d", set.Len(), before)
	}

	other := openAIPolicy(t, testKey(t))
	other.Provider = "anthropic"
	other.ProviderKey = nil
	if err := set.InstallAll([]Policy{good, other}, now); err != nil {
		t.Fatalf("InstallAll: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", set.Len())
	}
}

func TestPolicySetConcurrentAccess(t *testing.T) {
	key := testKey(t)
	set := NewSet()
	if err := set.Add(signedPolicy(t, key), now); err != nil {
		t.Fatalf("add: %v", err)
	}

	// A policy set is read on every job while policies are rotated in the
	// background, so concurrent access is the normal case, not an edge case.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 64; j++ {
				_ = set.Providers()
				if _, err := set.Authorize(spec(t, nil)); err != nil {
					t.Errorf("authorize under concurrency: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestSignedPolicyRoundTrip(t *testing.T) {
	key := testKey(t)
	signed := signedPolicy(t, key)

	encoded, err := signed.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeSignedPolicy(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := VerifySignedPolicy(decoded, now); err != nil {
		t.Fatalf("verify after round trip: %v", err)
	}

	originalHash, err := signed.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	decodedHash, err := decoded.Hash()
	if err != nil {
		t.Fatalf("hash decoded: %v", err)
	}
	if originalHash != decodedHash {
		t.Fatal("policy hash changed across a round trip")
	}
}

func TestIsQueryKey(t *testing.T) {
	valid := []string{"a", "include", "max_tokens", "a.b", "a-b", "a_b"}
	for _, key := range valid {
		if !isQueryKey(key) {
			t.Errorf("isQueryKey(%q) = false, want true", key)
		}
	}
	invalid := []string{"", "a[b]", "a%20b", "a b", "a=b", strings.Repeat("a", 65)}
	for _, key := range invalid {
		if isQueryKey(key) {
			t.Errorf("isQueryKey(%q) = true, want false", key)
		}
	}
}

func TestParseQueryKeys(t *testing.T) {
	keys, err := parseQueryKeys("b=2&a=1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 2 || keys[0] != "a" || keys[1] != "b" {
		t.Fatalf("keys = %v, want [a b]", keys)
	}

	if _, err := parseQueryKeys("%zz"); err == nil {
		t.Fatal("malformed percent-encoding accepted")
	}
	if _, err := parseQueryKeys("=1"); !errors.Is(err, ErrQueryNotAllowed) {
		t.Fatalf("empty key: error = %v, want %v", err, ErrQueryNotAllowed)
	}
	if keys, err := parseQueryKeys(""); err != nil || keys != nil {
		t.Fatalf("empty query: keys = %v, err = %v", keys, err)
	}
}

// TestPlaceholderCannotEscapeItsSegment guards the one rule that makes
// placeholders safe: they match a single path segment, never a slash.
func TestPlaceholderCannotEscapeItsSegment(t *testing.T) {
	key := testKey(t)
	policy := openAIPolicy(t, key)
	policy.Rules = []Rule{{
		Methods:   []string{"GET"},
		Path:      "/v1/models/{model}",
		QueryKeys: []string{"include"},
	}}

	// A placeholder filled with an encoded slash must not reach another path.
	for _, path := range []string{
		"/v1/models/gpt-4o/../../admin",
		"/v1/models/..",
	} {
		job := spec(t, func(s *jobs.Spec) {
			s.Method = "GET"
			s.Path = path
		})
		if _, err := policy.Authorize(job); err == nil {
			t.Errorf("placeholder rule admitted %q", path)
		}
	}
}

// TestPolicyUsesJobProviderRules asserts the policy package delegates provider
// name validation to jobs rather than keeping a second copy that can drift.
func TestPolicyUsesJobProviderRules(t *testing.T) {
	key := testKey(t)
	for _, name := range []string{"openai", "anthropic-2", "a_b", "OpenAI", "bad name", ""} {
		policy := openAIPolicy(t, key)
		policy.Provider = name

		policyErr := policy.Validate()
		jobErr := jobs.ValidateProviderName(name)
		if (policyErr == nil) != (jobErr == nil) {
			t.Errorf("provider %q: policy said %v, jobs said %v", name, policyErr, jobErr)
		}
	}
}

// TestVerifySignedPolicyUsesPlatformPath keeps the policy signature bound to
// the shared verification path: a signature made over a different domain must
// be rejected even though the key and algorithm are correct.
func TestVerifySignedPolicyUsesPlatformPath(t *testing.T) {
	key := testKey(t)
	signed := signedPolicy(t, key)

	policyHash, err := signed.Policy.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	digest, err := platform.SigningDigest("TokenHive.SomethingElse.v1", policyHash[:])
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	value, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	crossDomain := signed
	crossDomain.Signature.Value = value
	if err := VerifySignedPolicy(crossDomain, now); err == nil {
		t.Fatal("signature from another domain was accepted")
	}
}

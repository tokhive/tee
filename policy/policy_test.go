package policy

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

// Fixed clock so that expiry assertions do not depend on when the test runs.
var now = time.Unix(1_800_000_000, 0)

// openAIPolicy is a representative deployment whitelist: chat, embeddings,
// and one parametrised read path on a single host. It names no provider, which
// is the point — one document serves every seller agent.
func openAIPolicy() Policy {
	return Policy{
		Version: VersionV1,
		Hosts:   []string{"api.openai.com"},
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
		Limits: Limits{
			MaxResponseBytes: 1 << 20,
			MaxBodyBytes:     1 << 16,
			AllowedHeaders:   []string{"content-type", "openai-organization"},
		},
		IssuedAt:  now.Unix() - 3600,
		ExpiresAt: now.Unix() + 3600,
	}
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
	policy := openAIPolicy()

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
	cases := []struct {
		name   string
		want   error
		change func(*Policy)
	}{
		{
			name:   "unsupported version",
			want:   ErrUnsupportedVersion,
			change: func(p *Policy) { p.Version = 99 },
		},
		{
			name:   "no hosts",
			want:   ErrNoHosts,
			change: func(p *Policy) { p.Hosts = nil },
		},
		{
			name:   "too many hosts",
			want:   ErrNoHosts,
			change: func(p *Policy) { p.Hosts = make([]string, MaxHosts+1) },
		},
		{
			name:   "host with a path",
			want:   ErrInvalidHost,
			change: func(p *Policy) { p.Hosts = []string{"api.openai.com/v1"} },
		},
		{
			name:   "host with scheme",
			want:   ErrInvalidHost,
			change: func(p *Policy) { p.Hosts = []string{"https://api.openai.com"} },
		},
		{
			name:   "host with userinfo",
			want:   ErrInvalidHost,
			change: func(p *Policy) { p.Hosts = []string{"user@api.openai.com"} },
		},
		{
			name:   "duplicate hosts differ only in case",
			want:   ErrInvalidHost,
			change: func(p *Policy) { p.Hosts = []string{"Api.OpenAi.Com", "api.openai.com"} },
		},
		{
			name:   "no rules",
			want:   ErrNoRules,
			change: func(p *Policy) { p.Rules = nil },
		},
		{
			name:   "too many rules",
			want:   ErrNoRules,
			change: func(p *Policy) { p.Rules = make([]Rule, MaxRules+1) },
		},
		{
			name:   "rule with no methods",
			want:   ErrInvalidMethods,
			change: func(p *Policy) { p.Rules[0].Methods = nil },
		},
		{
			name:   "relative rule path",
			want:   ErrInvalidPathRule,
			change: func(p *Policy) { p.Rules[0].Path = "chat/completions" },
		},
		{
			name:   "partial placeholder",
			want:   ErrInvalidPathRule,
			change: func(p *Policy) { p.Rules[2].Path = "/v1/models/{model" },
		},
		{
			name:   "placeholder with a slash inside",
			want:   ErrInvalidPathRule,
			change: func(p *Policy) { p.Rules[2].Path = "/v1/models/{model/x}" },
		},
		{
			name:   "placeholder name too long",
			want:   ErrInvalidPathRule,
			change: func(p *Policy) { p.Rules[2].Path = "/v1/{" + strings.Repeat("x", MaxPlaceholderLen+1) + "}" },
		},
		{
			name:   "unsupported method",
			want:   ErrInvalidMethods,
			change: func(p *Policy) { p.Rules[0].Methods = []string{"HEAD"} },
		},
		{
			name:   "duplicate method",
			want:   ErrInvalidMethods,
			change: func(p *Policy) { p.Rules[0].Methods = []string{"GET", "get"} },
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
			name:   "duplicate header differing in case",
			want:   ErrInvalidHeaderName,
			change: func(p *Policy) { p.Limits.AllowedHeaders = []string{"content-type", "Content-Type"} },
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
			name:   "invalid query key",
			want:   ErrInvalidQueryKey,
			change: func(p *Policy) { p.Rules[2].QueryKeys = []string{"a[b]"} },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := openAIPolicy()
			tc.change(&policy)
			err := policy.Validate()
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPolicyValidateAtWindow(t *testing.T) {
	policy := openAIPolicy()

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

func TestAuthorizeAllowsMatchingJob(t *testing.T) {
	policy := openAIPolicy()

	decision, err := policy.Authorize(spec(t, nil))
	if err != nil {
		t.Fatalf("authorize: %v", err)
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
	policy := openAIPolicy()

	cases := []struct {
		name   string
		want   error
		change func(*jobs.Spec)
	}{
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
	policy := openAIPolicy()

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

func TestPolicyRoundTrip(t *testing.T) {
	policy := openAIPolicy()

	encoded, err := policy.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var decoded Policy
	if err := canonical.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// An indefinite-length map carries the same content in different bytes.
	// Accepting it would let one policy hash two ways.
	indefinite := append([]byte{0xbf}, encoded[1:]...)
	if err := canonical.Unmarshal(indefinite, &decoded); err == nil {
		t.Fatal("indefinite-length encoding was accepted")
	}

	originalHash, err := policy.Hash()
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
	policy := openAIPolicy()
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

// TestPolicyIsNotKeyedByProvider is the point of a singular whitelist: the same
// document authorises every seller agent identically, so no agent can hold — or
// declare — rules of its own.
func TestPolicyIsNotKeyedByProvider(t *testing.T) {
	policy := openAIPolicy()

	for _, agent := range []string{"openai-sim", "cheap-sim", "bee-9f3a"} {
		decision, err := policy.Authorize(spec(t, func(s *jobs.Spec) { s.Provider = agent }))
		if err != nil {
			t.Fatalf("agent %q refused by a whitelist that names no provider: %v", agent, err)
		}
		if len(decision.PolicyHash) == 0 {
			t.Fatalf("agent %q: decision names no policy revision", agent)
		}
	}
}

// TestAllowsRouteIsTheAdmissionLookup pins the host+path lookup the Hub performs
// at bring-up: it must answer, without a whole job, exactly what Authorize
// answers about where egress would go.
func TestAllowsRouteIsTheAdmissionLookup(t *testing.T) {
	policy := openAIPolicy()

	for _, ok := range []struct{ host, path, method string }{
		{"api.openai.com", "/v1/chat/completions", "POST"},
		{"api.openai.com", "/v1/embeddings", "POST"},
		{"api.openai.com", "/v1/models/gpt-4o", "GET"},
	} {
		if err := policy.AllowsRoute(ok.host, ok.path, ok.method); err != nil {
			t.Fatalf("admitted route %s %s%s refused: %v", ok.method, ok.host, ok.path, err)
		}
	}

	cases := []struct {
		name             string
		host, path, meth string
		want             error
	}{
		{"host outside the whitelist", "evil.example.com", "/v1/chat/completions", "POST", ErrHostNotAllowed},
		{"path outside the whitelist", "api.openai.com", "/v1/admin/keys", "POST", ErrPathNotAllowed},
		{"method outside the whitelist", "api.openai.com", "/v1/embeddings", "GET", ErrMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := policy.AllowsRoute(tc.host, tc.path, tc.meth); !errors.Is(err, tc.want) {
				t.Fatalf("AllowsRoute() error = %v, want %v", err, tc.want)
			}
		})
	}

	// An invalid document must not admit anything, however well-formed the
	// route looks: admission is a policy question, not a lookup that can be
	// answered from a broken file.
	broken := openAIPolicy()
	broken.Hosts = nil
	if err := broken.AllowsRoute("api.openai.com", "/v1/chat/completions", "POST"); !errors.Is(err, ErrNoHosts) {
		t.Fatalf("broken policy admitted a route: %v", err)
	}
}

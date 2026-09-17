package shared

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
)

// TestWritePolicyDirRoundTrips pins the "bake the whitelist into a policy
// directory" contract that -policy-dir, -emit-policy-dir and pack.sh rely on:
// WritePolicyDir materializes the deployment whitelist in the layout the loader
// reads, and SetPolicyDir redirects the loader to it — so the whitelist an SNP
// bundle carries (and the Hub advertises on /v1/policies) is the same document
// the TEE enforces, byte for byte.
func TestWritePolicyDirRoundTrips(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)
	t.Cleanup(func() { SetPolicyDir("") })

	policyDir := filepath.Join(simDir, "policy")
	if err := WritePolicyDir(policyDir); err != nil {
		t.Fatalf("WritePolicyDir: %v", err)
	}

	// Before the override is set, the loader points at the .sim dir, which holds
	// no policy.cbor, so loading must fail: nothing is silently inherited.
	if _, err := LoadPolicy(); err == nil {
		t.Fatal("LoadPolicy from an empty .sim should fail")
	}
	if got := PolicyDir(); got != simDir {
		t.Fatalf("PolicyDir() before override = %q, want %q", got, simDir)
	}

	SetPolicyDir(policyDir)
	if got := PolicyDir(); got != policyDir {
		t.Fatalf("PolicyDir() after override = %q, want %q", got, policyDir)
	}

	loaded, err := LoadPolicy()
	if err != nil {
		t.Fatalf("LoadPolicy from the policy dir: %v", err)
	}
	want := defaultPolicy(t)
	if len(loaded.Hosts) != len(want.Hosts) {
		t.Fatalf("hosts = %v, want %v", loaded.Hosts, want.Hosts)
	}
	for i := range want.Hosts {
		if loaded.Hosts[i] != want.Hosts[i] {
			t.Fatalf("host %d = %q, want %q", i, loaded.Hosts[i], want.Hosts[i])
		}
	}
	if len(loaded.Rules) != len(want.Rules) {
		t.Fatalf("%d rules, want %d", len(loaded.Rules), len(want.Rules))
	}

	// Reloading must yield the same bytes, hence the same hash: that is what
	// lets the hash stand in for the whitelist in a receipt or an audit log.
	again, err := LoadPolicy()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	gotHash, err := loaded.Hash()
	if err != nil {
		t.Fatalf("hash loaded policy: %v", err)
	}
	againHash, err := again.Hash()
	if err != nil {
		t.Fatalf("hash reloaded policy: %v", err)
	}
	if gotHash != againHash {
		t.Fatalf("policy hash changed across a reload: %x vs %x", gotHash, againHash)
	}
}

// TestStalePerProviderPoliciesAreIgnored pins the retirement of the per-provider
// layout. A policies/<provider>.cbor left behind by the multi-policy era must
// not change what the enclave enforces: sellers do not get to bring their own
// rules, and neither do their leftovers.
func TestStalePerProviderPoliciesAreIgnored(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)
	t.Cleanup(func() { SetPolicyDir("") })

	if err := WritePolicyDir(simDir); err != nil {
		t.Fatalf("WritePolicyDir: %v", err)
	}
	before, err := LoadPolicy()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	beforeHash, err := before.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// A wider whitelist, at the path an older deployment would have used.
	stale := defaultPolicy(t)
	stale.Hosts = append(stale.Hosts, "evil.example.com")
	enc, err := stale.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode stale policy: %v", err)
	}
	staleDir := filepath.Join(simDir, "policies")
	if err := os.MkdirAll(staleDir, 0o755); err != nil {
		t.Fatalf("make stale dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(staleDir, "openai-sim.cbor"), enc, 0o644); err != nil {
		t.Fatalf("write stale policy: %v", err)
	}

	after, err := LoadPolicy()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	afterHash, err := after.Hash()
	if err != nil {
		t.Fatalf("hash after: %v", err)
	}
	if beforeHash != afterHash {
		t.Fatal("a leftover per-provider policy changed the deployment whitelist")
	}
	if err := after.AllowsRoute("evil.example.com", "/v1/chat/completions", "POST"); err == nil {
		t.Fatal("a leftover per-provider policy widened the hosts the enclave reaches")
	}
}

// TestDefaultPolicyCoversTheRealAPIs pins the two upstreams the public default
// whitelist exists to admit, on the shapes the Hub serves them with: a seller
// onboards against this document, so dropping either API would silently make
// every seller of that shape unadmittable.
func TestDefaultPolicyCoversTheRealAPIs(t *testing.T) {
	p := defaultPolicy(t)

	for _, r := range []struct{ host, path, method string }{
		{"api.openai.com", "/v1/chat/completions", "POST"},
		{"api.openai.com", "/v1/responses", "POST"},
		{"api.anthropic.com", "/v1/messages", "POST"},
		{"chatgpt.com", "/backend-api/codex/responses", "POST"},
	} {
		if err := p.AllowsRoute(r.host, r.path, r.method); err != nil {
			t.Errorf("%s %s%s not admitted by the default policy: %v", r.method, r.host, r.path, err)
		}
	}

	// A host the deployment does not reach is still refused, so admitting the
	// real APIs did not turn the whitelist into a wildcard.
	if err := p.AllowsRoute("evil.example.com", "/v1/chat/completions", "POST"); err == nil {
		t.Error("the default policy admitted a host it does not name")
	}
}

// TestResolvePolicyDir pins the one rule for where a whitelist comes from. The
// measured bundle wins over the state directory, because rules read from
// outside the measurement are rules the attestation says nothing about; an
// explicit setting wins over both.
func TestResolvePolicyDir(t *testing.T) {
	root := t.TempDir()
	old := bundleRoot
	bundleRoot = root
	t.Cleanup(func() { bundleRoot = old })

	measured := filepath.Join(root, "policy")
	if err := WritePolicyDir(measured); err != nil {
		t.Fatalf("WritePolicyDir: %v", err)
	}

	cases := []struct {
		name       string
		configured string
		want       string
	}{
		{"nothing configured, measured bundle present", "", measured},
		{"explicit setting wins", "/operator/policy", "/operator/policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolvePolicyDir(tc.configured); got != tc.want {
				t.Fatalf("ResolvePolicyDir(%q) = %q, want %q", tc.configured, got, tc.want)
			}
		})
	}

	// A bundle that carries no whitelist resolves to nothing rather than to
	// some other directory: the caller decides the fallback, so a missing
	// measured policy can never be quietly satisfied by an unrelated file.
	empty := t.TempDir()
	bundleRoot = empty
	if got := ResolvePolicyDir(""); got != "" {
		t.Fatalf("ResolvePolicyDir() = %q with no policy in the bundle, want empty", got)
	}
}

// TestEnsureDefaultsLeavesAConfiguredPolicyAlone pins that the fixture writer
// does not drop a second, generated whitelist beside a directory the operator
// configured. Two policy files, one enforced and one merely present, is exactly
// how the policy a deployment runs drifts from the policy it measures.
func TestEnsureDefaultsLeavesAConfiguredPolicyAlone(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)
	t.Cleanup(func() { SetPolicyDir("") })

	SetPolicyDir(t.TempDir())
	if err := EnsureDefaults(); err != nil {
		t.Fatalf("EnsureDefaults: %v", err)
	}
	if _, err := os.Stat(filepath.Join(simDir, "policy.cbor")); err == nil {
		t.Fatal("EnsureDefaults wrote a whitelist beside a configured policy directory")
	}
	// The rate table is not policy: the Hub still needs it.
	if _, err := os.Stat(filepath.Join(simDir, "rates.json")); err != nil {
		t.Fatalf("EnsureDefaults must still write the rate table: %v", err)
	}

	// With nothing configured, the simulation's own whitelist is materialized
	// and loadable.
	SetPolicyDir("")
	if err := EnsureDefaults(); err != nil {
		t.Fatalf("EnsureDefaults: %v", err)
	}
	if _, err := LoadPolicy(); err != nil {
		t.Fatalf("the simulation whitelist should be loadable: %v", err)
	}
}

// TestDefaultPolicyIsReproducible pins that the shipped whitelist is a function
// of the code alone. Its bytes are measured, so a document that changed on
// every generation would move SNP_APP_HASH with no code change and leave the
// artifact irreproducible — which is also what lets a build re-emit the policy
// on every run instead of freezing a copy that silently goes stale.
func TestDefaultPolicyIsReproducible(t *testing.T) {
	first, err := defaultPolicy(t).Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// Round-trip through the filesystem as well, so the encoder and the loader
	// are in the loop and not just the in-memory document.
	dir := t.TempDir()
	if err := WritePolicyDir(dir); err != nil {
		t.Fatalf("WritePolicyDir: %v", err)
	}
	t.Cleanup(func() { SetPolicyDir("") })
	SetPolicyDir(dir)
	loaded, err := LoadPolicy()
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	again, err := loaded.Hash()
	if err != nil {
		t.Fatalf("hash loaded: %v", err)
	}
	if first != again {
		t.Fatal("the default whitelist is not reproducible across generations")
	}
}

// TestDefaultPolicyDoesNotLapse pins the "the public default whitelist is
// open-ended" contract. The default policy is what every seller onboards
// against, so a finite window would eventually start refusing every job with
// ErrPolicyExpired while the policy file itself still looked correct — a
// failure that only shows up as refusals, long after the change that caused it.
func TestDefaultPolicyDoesNotLapse(t *testing.T) {
	// ~year 36812: far past any finite grant yet still a representable
	// timestamp, so an open-ended policy passes and a term of years fails.
	far := time.Unix(1<<40, 0)

	p := defaultPolicy(t)
	if err := p.Validate(); err != nil {
		t.Fatalf("policy.Default().Validate: %v", err)
	}
	if err := p.ValidateAt(far); err != nil {
		t.Fatalf("default policy lapsed before t=%d: %v", far.Unix(), err)
	}
}

// defaultPolicy is the shipped deployment whitelist, for the tests that need to
// compare a loaded policy against it. It is policy.Default — the document in
// tokenhive/policy/whitelist.json — reached through the same call the runtime
// makes, so a document that stopped parsing fails here rather than in a test
// fixture that had its own copy.
func defaultPolicy(t *testing.T) policy.Policy {
	t.Helper()
	p, err := policy.Default()
	if err != nil {
		t.Fatalf("policy.Default: %v", err)
	}
	return p
}

package shared

import (
	"path/filepath"
	"sort"
	"testing"
)

// TestWritePolicyDirRoundTrips pins the "bake the whitelist into a policy
// directory" contract that -policy-dir and pack.sh rely on: WritePolicyDir
// materializes the canonical white-list in the exact on-disk layout
// LoadPolicySetAll reads, and SetPolicyDir redirects the loaders to it — so the
// whitelist an SNP bundle carries (and the Hub advertises on /v1/policies) is
// the same set the TEE enforces, byte for byte.
func TestWritePolicyDirRoundTrips(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)
	t.Cleanup(func() { SetPolicyDir("") })

	policyDir := filepath.Join(simDir, "policy")
	if err := WritePolicyDir(policyDir); err != nil {
		t.Fatalf("WritePolicyDir: %v", err)
	}

	// Before the override is set, the loaders point at the .sim dir, which holds
	// no policy.cbor, so loading must fail: nothing is silently inherited.
	if _, err := LoadPolicySetAll(); err == nil {
		t.Fatal("LoadPolicySetAll from an empty .sim should fail")
	}
	if got := PolicyDir(); got != simDir {
		t.Fatalf("PolicyDir() before override = %q, want %q", got, simDir)
	}

	SetPolicyDir(policyDir)
	if got := PolicyDir(); got != policyDir {
		t.Fatalf("PolicyDir() after override = %q, want %q", got, policyDir)
	}
	set, err := LoadPolicySetAll()
	if err != nil {
		t.Fatalf("LoadPolicySetAll from the policy dir: %v", err)
	}

	providers := set.Providers()
	sort.Strings(providers)
	want := []string{"cheap-sim", "openai-sim"}
	if len(providers) != len(want) {
		t.Fatalf("Providers() = %v, want %v", providers, want)
	}
	for i := range want {
		if providers[i] != want[i] {
			t.Fatalf("Providers() = %v, want %v", providers, want)
		}
	}

	// The set the dir round-trips must be exactly the canonical one: same hash.
	canonical, err := LoadPolicySetAll()
	if err != nil {
		t.Fatalf("reload canonical: %v", err)
	}
	gotHash, err := set.Hash()
	if err != nil {
		t.Fatalf("hash round-tripped set: %v", err)
	}
	canonicalHash, err := canonical.Hash()
	if err != nil {
		t.Fatalf("hash canonical set: %v", err)
	}
	if gotHash != canonicalHash {
		t.Fatalf("round-tripped set hash %x != canonical %x", gotHash, canonicalHash)
	}
}
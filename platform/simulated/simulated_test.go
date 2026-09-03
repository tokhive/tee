package simulated

import (
	"encoding/json"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

func TestDeploymentEpochBindsPolicySetHash(t *testing.T) {
	var want [32]byte
	for i := range want {
		want[i] = byte(i + 1)
	}

	epoch, err := NewDeploymentEpoch(want)
	if err != nil {
		t.Fatalf("new deployment epoch: %v", err)
	}
	identity := epoch.Identity()

	// The evidence must carry the bound hash so a verifier can confirm which
	// whitelist configuration the enclave was deployed with.
	var ev SimEvidence
	if err := json.Unmarshal(identity.Evidence, &ev); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	if ev.PolicySetHash == "" {
		t.Fatal("deployment epoch evidence carries no policy-set hash")
	}
	if got := ev.PolicySetHash; got != hexOf(want) {
		t.Fatalf("evidence policy-set hash = %q, want %q", got, hexOf(want))
	}

	// The verifier-side check passes for the bound hash...
	if err := CheckEvidenceForDeployment(identity, want); err != nil {
		t.Fatalf("check deployment evidence: %v", err)
	}
	// ...and fails for a different configuration.
	var other [32]byte
	other[0] = 0xff
	if err := CheckEvidenceForDeployment(identity, other); err == nil {
		t.Fatal("evidence accepted with the wrong policy-set hash")
	}

	// The binding is part of the evidence hash: a plain epoch (no deployment)
	// produces different evidence than a bound one.
	plain, err := NewEpoch()
	if err != nil {
		t.Fatalf("new plain epoch: %v", err)
	}
	if plain.Identity().EvidenceHash == identity.EvidenceHash {
		t.Fatal("deployment-bound evidence hashes identically to a plain epoch")
	}
}

func TestDeploymentCheckRejectsPlainEpoch(t *testing.T) {
	epoch, err := NewEpoch()
	if err != nil {
		t.Fatalf("new epoch: %v", err)
	}
	var want [32]byte
	if err := CheckEvidenceForDeployment(epoch.Identity(), want); err == nil {
		t.Fatal("plain epoch accepted by the deployment check")
	}
}

func hexOf(h [32]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range h {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0xf]
	}
	return string(out)
}

var _ platform.Epoch = (*epoch)(nil)

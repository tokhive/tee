//go:build !mobile

package sevsnp

import (
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// The whitelist is staged into the measured bundle, so the attested application
// identity covers the policy bytes the enclave enforces and the deployment
// binding is the image check. These pin the two halves of that: without an
// expected image nothing pins the policy, so the binding must refuse; with one
// the binding must be exactly the image check and must not be weakened by the
// digest it is handed.
func TestCheckEvidenceForDeploymentNeedsAnExpectedImage(t *testing.T) {
	v := Verifier{}
	for _, h := range []struct {
		name string
		hash [32]byte
	}{
		{name: "zero digest", hash: [32]byte{}},
		{name: "non-zero digest", hash: [32]byte{1, 2, 3}},
	} {
		t.Run(h.name, func(t *testing.T) {
			err := v.CheckEvidenceForDeployment(platform.Identity{Platform: platform.PlatformAWSSEVSNP}, h.hash)
			if err == nil {
				t.Fatal("deployment binding accepted evidence with no expected application identity")
			}
			if !strings.Contains(err.Error(), "expected application identity") {
				t.Fatalf("refusal did not name its reason: %v", err)
			}
		})
	}
}

func TestCheckEvidenceForDeploymentIsTheImageCheck(t *testing.T) {
	v := Verifier{ExpectedApp: "snp-app:" + strings.Repeat("ab", 32)}
	id := platform.Identity{Platform: platform.PlatformAWSSEVSNP}

	want := v.CheckEvidence(id)
	if want == nil {
		t.Fatal("the fixture stopped producing a verifiable failure")
	}
	for _, h := range [][32]byte{{}, {1, 2, 3}, {255}} {
		got := v.CheckEvidenceForDeployment(id, h)
		if got == nil || got.Error() != want.Error() {
			t.Fatalf("deployment binding diverged from the image check: %v, want %v", got, want)
		}
	}
}

func TestCheckEvidenceRefusesAnotherPlatform(t *testing.T) {
	v := Verifier{ExpectedApp: "snp-app:" + strings.Repeat("ab", 32)}
	if err := v.CheckEvidenceForDeployment(platform.Identity{Platform: "simulated"}, [32]byte{}); err == nil {
		t.Fatal("deployment binding accepted an identity from another platform")
	}
}

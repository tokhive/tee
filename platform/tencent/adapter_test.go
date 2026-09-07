package tencent

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/dev"
)

func devEpoch() (platform.Epoch, error) {
	return dev.NewEpoch(platform.PlatformTencentCloud, "test")
}

func fakeDetect(tech string, ok bool) func() (string, bool) {
	return func() (string, bool) { return tech, ok }
}

func TestNewTencentCloudFailsOnNonTencentHost(t *testing.T) {
	_, err := newAdapter(Config{}, fakeDetect("", false))
	if err == nil {
		t.Fatal("expected an error on a non-Tencent host")
	}
	if errors.Is(err, platform.ErrAttestationNotImplemented) {
		t.Fatalf("host detection must precede the attestation gate, got: %v", err)
	}
}

func TestNewTencentCloudFailsClosedWithoutAllowUntrusted(t *testing.T) {
	_, err := newAdapter(Config{}, fakeDetect("intel-sgx", true))
	if err == nil {
		t.Fatal("expected the skeleton to refuse a trusted start")
	}
	if !errors.Is(err, platform.ErrAttestationNotImplemented) {
		t.Fatalf("expected ErrAttestationNotImplemented, got: %v", err)
	}
}

func TestNewTencentCloudAllowUntrustedMintsCloudEpoch(t *testing.T) {
	a, err := newAdapter(Config{Role: "tokenhive-tee", AllowUntrusted: true}, fakeDetect("amd-sev-snp", true))
	if err != nil {
		t.Fatalf("newAdapter: %v", err)
	}
	if !a.Healthy() {
		t.Fatal("adapter should be healthy in AllowUntrusted wiring mode")
	}
	epoch, err := a.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	id := epoch.Identity()
	if id.Platform != platform.PlatformTencentCloud {
		t.Fatalf("dev epoch must carry the tencent platform string, got %q", id.Platform)
	}
	if id.AttestationType != "dev-unattested" {
		t.Fatalf("dev epoch must be labelled unattested, got %q", id.AttestationType)
	}
	if err := (Verifier{}).CheckEvidence(id); !errors.Is(err, platform.ErrAttestationNotImplemented) {
		t.Fatalf("cloud verifier must refuse the dev epoch with ErrAttestationNotImplemented, got: %v", err)
	}
	if cfg := a.ServerTLSConfig(); cfg == nil {
		t.Fatal("server TLS config must exist in wiring mode")
	}
}

func TestNewTencentCloudRefreshIsNoop(t *testing.T) {
	a, err := newAdapter(Config{AllowUntrusted: true}, fakeDetect("intel-tdx", true))
	if err != nil {
		t.Fatalf("newAdapter: %v", err)
	}
	if err := a.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh should be a no-op in the skeleton, got: %v", err)
	}
}

func TestVerifierRefusesUnimplementedEvidence(t *testing.T) {
	epoch, err := devEpoch()
	if err != nil {
		t.Fatalf("dev epoch: %v", err)
	}
	id := epoch.Identity()
	if err := (Verifier{}).CheckEvidence(id); !errors.Is(err, platform.ErrAttestationNotImplemented) {
		t.Fatalf("expected ErrAttestationNotImplemented, got: %v", err)
	}
	if err := (Verifier{}).CheckEvidenceForDeployment(id, [32]byte{}); !errors.Is(err, platform.ErrAttestationNotImplemented) {
		t.Fatalf("expected ErrAttestationNotImplemented from deployment check, got: %v", err)
	}
}

func TestVerifierStructuralChecks(t *testing.T) {
	epoch, err := devEpoch()
	if err != nil {
		t.Fatalf("dev epoch: %v", err)
	}
	id := epoch.Identity()

	wrong := id
	wrong.Platform = platform.PlatformAWSSEVSNP
	if err := (Verifier{}).CheckEvidence(wrong); err == nil {
		t.Fatal("expected a platform mismatch error")
	}

	noEvidence := id
	noEvidence.Evidence = nil
	if err := (Verifier{}).CheckEvidence(noEvidence); err == nil {
		t.Fatal("expected a missing-evidence error")
	}

	badHash := id
	badHash.EvidenceHash = sha256.Sum256([]byte("tampered"))
	if err := (Verifier{}).CheckEvidence(badHash); err == nil {
		t.Fatal("expected a hash mismatch error")
	}
}

func TestPlatformString(t *testing.T) {
	if got := (Verifier{}).Platform(); got != platform.PlatformTencentCloud {
		t.Fatalf("verifier platform = %q", got)
	}
}

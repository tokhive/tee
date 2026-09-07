package dev

import (
	"crypto/tls"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

func TestNewEpochCarriesCloudPlatform(t *testing.T) {
	epoch, err := NewEpoch(platform.PlatformAlibabaCloud, "tokenhive-tee")
	if err != nil {
		t.Fatalf("NewEpoch: %v", err)
	}
	id := epoch.Identity()
	if id.Platform != platform.PlatformAlibabaCloud {
		t.Fatalf("platform = %q, want %q", id.Platform, platform.PlatformAlibabaCloud)
	}
	if id.AttestationType != AttestationType {
		t.Fatalf("attestation type = %q, want %q", id.AttestationType, AttestationType)
	}
}

func TestNewEpochRejectsEmptyInputs(t *testing.T) {
	if _, err := NewEpoch("", "app"); err == nil {
		t.Fatal("expected an error for an empty platform")
	}
	if _, err := NewEpoch("alicloud", ""); err == nil {
		t.Fatal("expected an error for an empty application id")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	epoch, err := NewEpoch(platform.PlatformTencentCloud, "tokenhive-tee")
	if err != nil {
		t.Fatalf("NewEpoch: %v", err)
	}
	id := epoch.Identity()
	sig, err := epoch.Sign("test-domain", []byte("payload"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := platform.VerifySignature(id, "test-domain", []byte("payload"), sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := platform.VerifySignature(id, "other-domain", []byte("payload"), sig); err == nil {
		t.Fatal("signature must not verify under a different domain")
	}
}

func TestServerTLSConfigMintsFromDevKey(t *testing.T) {
	epoch, err := NewEpoch(platform.PlatformAlibabaCloud, "tokenhive-tee")
	if err != nil {
		t.Fatalf("NewEpoch: %v", err)
	}
	s, ok := epoch.(interface{ ServerTLSConfig() *tls.Config })
	if !ok {
		t.Fatal("dev epoch must expose ServerTLSConfig for the -mtls wiring")
	}
	cfg := s.ServerTLSConfig()
	if cfg == nil {
		t.Fatal("server TLS config must not be nil")
	}
	if len(cfg.Certificates) == 0 && cfg.GetCertificate == nil {
		t.Fatal("server TLS config must carry a certificate")
	}
}

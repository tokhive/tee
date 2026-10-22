//go:build !mobile

package shared

import (
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

// TestNewRATLSManager_StandaloneFallback verifies that NewRATLSManager
// produces a usable cert even when the GCP Confidential Space launcher
// socket is absent (i.e. local dev). The attestation extension is then
// missing — that's expected and documented.
func TestNewRATLSManager_StandaloneFallback(t *testing.T) {
	m, err := NewRATLSManager(t.Context(), "tee_k", nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if m.Certificate() == nil || m.CertificateRaw() == nil {
		t.Fatal("expected non-nil cert")
	}

	leaf, err := x509.ParseCertificate(m.CertificateRaw())
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Subject.CommonName != "tee_k" {
		t.Fatalf("subject CN = %q, want tee_k", leaf.Subject.CommonName)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("expected DigitalSignature key usage")
	}

	// Standalone mode: launcher socket isn't there, so the extension is absent.
	// This test runs outside an enclave, so confirm that's what we see.
	if _, err := ExtractAttestationFromCert(leaf); err == nil {
		t.Fatal("expected ExtractAttestationFromCert to fail in standalone mode")
	}
}

// TestRATLSManager_SPKIHashStable confirms the SPKI hash reported by the
// manager matches what an external verifier would compute from the public
// key in the cert.
func TestRATLSManager_SPKIHashStable(t *testing.T) {
	m, err := NewRATLSManager(t.Context(), "tee_t", nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	leaf, err := x509.ParseCertificate(m.CertificateRaw())
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	expected := sha256.Sum256(spkiDER)

	if got := m.SPKIHash(); got != expected {
		t.Fatalf("SPKIHash mismatch:\n  manager: %x\n  cert:    %x", got, expected)
	}
}

// TestRATLSManager_DistinctInstancesGetDistinctKeys ensures each manager
// generates a fresh keypair (cert reuse across enclave restarts would
// leak whatever the previous key signed).
func TestRATLSManager_DistinctInstancesGetDistinctKeys(t *testing.T) {
	a, _ := NewRATLSManager(t.Context(), "tee_k", nil)
	b, _ := NewRATLSManager(t.Context(), "tee_k", nil)
	if a.SPKIHash() == b.SPKIHash() {
		t.Fatal("two managers produced identical SPKI hashes — keys are not fresh")
	}
}

// TestSPKIHashFromCertDER_MatchesManager verifies the helper returns the
// same value as RATLSManager.SPKIHash() — so all callers (TEEs computing
// the nonce, peers verifying it, client verifying it) agree exactly.
func TestSPKIHashFromCertDER_MatchesManager(t *testing.T) {
	m, err := NewRATLSManager(t.Context(), "tee_k", nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	want := m.SPKIHash()
	got, err := SPKIHashFromCertDER(m.CertificateRaw())
	if err != nil {
		t.Fatalf("SPKIHashFromCertDER: %v", err)
	}
	if got != want {
		t.Fatalf("SPKIHashFromCertDER mismatch:\n  manager: %x\n  helper:  %x", want, got)
	}
}

// TestSPKIHashFromCertDER_RotatesAcrossRefresh verifies the keypair (and thus
// the SPKI hash) is regenerated on every Refresh — the forward-secrecy property
// that bounds a key-extraction's blast radius to one refresh interval.
func TestSPKIHashFromCertDER_RotatesAcrossRefresh(t *testing.T) {
	m, err := NewRATLSManager(t.Context(), "tee_k", nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	certBefore := m.CertificateRaw()
	hashBefore, err := SPKIHashFromCertDER(certBefore)
	if err != nil {
		t.Fatalf("hash before: %v", err)
	}

	if err := m.Refresh(t.Context()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	certAfter := m.CertificateRaw()
	if string(certBefore) == string(certAfter) {
		t.Fatal("Refresh should have changed the cert DER")
	}
	hashAfter, err := SPKIHashFromCertDER(certAfter)
	if err != nil {
		t.Fatalf("hash after: %v", err)
	}
	if hashBefore == hashAfter {
		t.Fatalf("SPKI hash did NOT change across refresh; keypair should rotate:\n  before: %x\n  after:  %x", hashBefore, hashAfter)
	}
}

func TestSPKINoncePrefix(t *testing.T) {
	if got := SPKINoncePrefix("tee_k"); got != "tee_k_spki_hash:" {
		t.Fatalf("tee_k prefix: %q", got)
	}
	if got := SPKINoncePrefix("tee_t"); got != "tee_t_spki_hash:" {
		t.Fatalf("tee_t prefix: %q", got)
	}
}

// TestRATLSManager_RefreshRotatesCert verifies that Refresh produces a
// different cert (new serial) AND a fresh keypair (new SPKI). In-flight TLS
// sessions keep their handshake-time cert; new handshakes get the new one.
func TestRATLSManager_RefreshRotatesCert(t *testing.T) {
	m, err := NewRATLSManager(t.Context(), "tee_k", nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	before := m.Certificate()
	beforeSPKI := m.SPKIHash()

	if err := m.Refresh(t.Context()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	after := m.Certificate()
	afterSPKI := m.SPKIHash()

	if before == after {
		t.Fatal("expected Refresh to swap the cert pointer")
	}
	if before.Leaf.SerialNumber.Cmp(after.Leaf.SerialNumber) == 0 {
		t.Fatal("expected new serial after Refresh")
	}
	if beforeSPKI == afterSPKI {
		t.Fatal("SPKI hash must change across Refresh (keypair rotates)")
	}
}

// TestRATLSManager_GetCertificateAfterRefresh confirms a tls.Config wired
// up with GetCertificate sees the latest cert after a Refresh — this is
// the property that lets in-flight TLS configs auto-pick-up rotations.
func TestRATLSManager_GetCertificateAfterRefresh(t *testing.T) {
	m, err := NewRATLSManager(t.Context(), "tee_k", nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	before, err := m.GetCertificate(nil)
	if err != nil {
		t.Fatalf("get cert: %v", err)
	}
	if err := m.Refresh(t.Context()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	after, err := m.GetCertificate(nil)
	if err != nil {
		t.Fatalf("get cert after refresh: %v", err)
	}
	if before.Leaf.SerialNumber.Cmp(after.Leaf.SerialNumber) == 0 {
		t.Fatal("GetCertificate returned the old cert after Refresh")
	}
}

// TestIsEnclaveMode_LocalDev: on the developer machine running this test,
// the launcher socket should not exist.
func TestIsEnclaveMode_LocalDev(t *testing.T) {
	if IsEnclaveMode() {
		t.Skip("running on a machine with the Confidential Space launcher socket present — unusual for local dev")
	}
}

// TestRATLSLeafWindowIsLongLived pins why the attested leaf's own time window
// is long. It is not the freshness mechanism: freshness lives in the evidence
// (hours, on AWS) and in the refresher that re-signs on the platform cadence.
// The window is consulted only by consumers that do strict chain checks — among
// them a pin on this exact certificate — so a window on the order of a day
// makes every such consumer stop authenticating a TEE whose evidence is
// perfectly fresh, exactly one boot-and-forget interval later. The unit is not
// the point; "years" is.
func TestRATLSLeafWindowIsLongLived(t *testing.T) {
	m, err := NewRATLSManager(t.Context(), "tee_k", nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	leaf, err := x509.ParseCertificate(m.CertificateRaw())
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.NotAfter.Before(leaf.NotBefore.AddDate(1, 0, 0)) {
		t.Fatalf("RA-TLS leaf window is %v; a strict chain check would reject this TEE long before its evidence is stale",
			leaf.NotAfter.Sub(leaf.NotBefore))
	}
}

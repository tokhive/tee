package shared

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
)

func TestSecureBootAuthorityPolicy(t *testing.T) {
	valid := secureBootAuthorityPolicy{
		enabled: true, permittedKeys: 1, releaseDBEntries: 1,
		postAuthorities: 1, releasePostAuthorities: 1,
	}
	if !secureBootAuthorityPolicyOK(valid) {
		t.Fatal("valid R-only policy rejected")
	}

	tests := map[string]func(*secureBootAuthorityPolicy){
		"disabled":            func(p *secureBootAuthorityPolicy) { p.enabled = false },
		"additional db key":   func(p *secureBootAuthorityPolicy) { p.permittedKeys = 2 },
		"permitted hash":      func(p *secureBootAuthorityPolicy) { p.permittedHashes = 1 },
		"R absent from db":    func(p *secureBootAuthorityPolicy) { p.releaseDBEntries = 0 },
		"R revoked":           func(p *secureBootAuthorityPolicy) { p.releaseDBXEntries = 1 },
		"pre-boot authority":  func(p *secureBootAuthorityPolicy) { p.preAuthorities = 1 },
		"no executed image":   func(p *secureBootAuthorityPolicy) { p.postAuthorities = 0; p.releasePostAuthorities = 0 },
		"foreign signer used": func(p *secureBootAuthorityPolicy) { p.postAuthorities = 2; p.releasePostAuthorities = 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			policy := valid
			mutate(&policy)
			if secureBootAuthorityPolicyOK(policy) {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

// A refusal that says only "not R-only" sends the operator back to guessing:
// the same sentence covers the old certificate still sitting in db and the log
// recording no post-separator authority at all. The report has to name every
// count the decision reads, with the failing one visible in it.
func TestSecureBootPolicyReportNamesTheFailingClause(t *testing.T) {
	valid := secureBootAuthorityPolicy{
		enabled: true, permittedKeys: 1, releaseDBEntries: 1,
		postAuthorities: 1, releasePostAuthorities: 1,
	}
	if ok := secureBootAuthorityPolicyOK(valid); !ok {
		t.Fatal("fixture must be a passing policy")
	}
	report := secureBootPolicyReport(valid)
	for _, want := range []string{"enabled=true", "dbKeys=1", "dbHashes=0", "dbR=1",
		"dbxR=0", "preAuthorities=0", "postAuthorities=1", "postR=1"} {
		if !strings.Contains(report, want) {
			t.Fatalf("report is missing %q: %s", want, report)
		}
	}

	// The two failures that read identically in the one-line message must not
	// read identically here.
	staleDB := valid
	staleDB.releaseDBEntries = 0
	noPost := valid
	noPost.postAuthorities, noPost.releasePostAuthorities = 0, 0
	if a, b := secureBootPolicyReport(staleDB), secureBootPolicyReport(noPost); a == b {
		t.Fatalf("distinct failures produced the same report: %s", a)
	}
}

// A Hub logs this next to a successful attestation and an operator compares it
// with the AMI's R.pub.pem, so it has to describe the key the verifier actually
// uses -- not a second parse that could drift from it.
func TestReleasePublicKeyFingerprintIsTheVerifiedKey(t *testing.T) {
	fp, err := ReleasePublicKeySHA256()
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if len(fp) != 64 || strings.Trim(fp, "0123456789abcdef") != "" {
		t.Fatalf("fingerprint is not 32 bytes of lowercase hex: %q", fp)
	}
	spki, err := releasePublicKeySPKI()
	if err != nil {
		t.Fatalf("embedded SPKI: %v", err)
	}
	if want := fmt.Sprintf("%x", sha256.Sum256(spki)); fp != want {
		t.Fatalf("reported %s, verifier uses %s", fp, want)
	}
}

// releaseKeyPEM builds a throwaway key the way an operator's file would look.
func releaseKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// Rotation should not mean rebuilding the verifier: a deployment hands its key
// in, and every path in this package -- verification, the reported fingerprint --
// has to follow it.
func TestConfiguredReleaseKeyReplacesTheEmbeddedOne(t *testing.T) {
	embedded, err := ReleasePublicKeySHA256()
	if err != nil {
		t.Fatalf("embedded fingerprint: %v", err)
	}
	configured := releaseKeyPEM(t)
	if err := SetReleasePublicKeyPEM(configured); err != nil {
		t.Fatalf("set: %v", err)
	}
	t.Cleanup(func() {
		if err := SetReleasePublicKeyPEM(nil); err != nil {
			t.Fatalf("restore: %v", err)
		}
	})

	spki, err := releasePublicKeySPKI()
	if err != nil {
		t.Fatalf("spki: %v", err)
	}
	want := fmt.Sprintf("%x", sha256.Sum256(spki))
	got, err := ReleasePublicKeySHA256()
	if err != nil {
		t.Fatalf("configured fingerprint: %v", err)
	}
	if got != want {
		t.Fatalf("reported %s, verifier uses %s", got, want)
	}
	if got == embedded {
		t.Fatal("configured key did not replace the embedded one")
	}
}

// Clearing the override has to restore the embedded key, or a test (or a
// reconfiguration) would leave the process on a key nobody chose.
func TestClearingTheConfiguredReleaseKeyRestoresTheEmbeddedOne(t *testing.T) {
	embedded, err := ReleasePublicKeySHA256()
	if err != nil {
		t.Fatalf("embedded fingerprint: %v", err)
	}
	if err := SetReleasePublicKeyPEM(releaseKeyPEM(t)); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := SetReleasePublicKeyPEM(nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	got, err := ReleasePublicKeySHA256()
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if got != embedded {
		t.Fatalf("after clearing, verifier still uses %s", got)
	}
}

// A key that cannot be parsed must fail loudly: falling back to the embedded
// copy would verify with a key the operator is not looking at.
func TestAnUnparsableConfiguredReleaseKeyIsRejected(t *testing.T) {
	embedded, err := ReleasePublicKeySHA256()
	if err != nil {
		t.Fatalf("embedded fingerprint: %v", err)
	}
	for _, bad := range [][]byte{[]byte("not a pem block"), {}, []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")} {
		if err := SetReleasePublicKeyPEM(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	got, err := ReleasePublicKeySHA256()
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if got != embedded {
		t.Fatalf("a rejected key changed what the verifier uses: %s", got)
	}
}

func TestVerifyTypedSNPNonceAttestationDispatch(t *testing.T) {
	tests := []struct {
		name            string
		attestationType string
		report          []byte
		want            string
	}{
		{
			name:            "unknown type",
			attestationType: "future-type",
			want:            "unsupported attestation type",
		},
		{
			name:            "secure type requires secure evidence tag",
			attestationType: AttestationTypeSecureBoot,
			report:          []byte{snpAttestTagGCP},
			want:            "does not carry Secure Boot evidence",
		},
		{
			name:            "legacy type rejects secure evidence tag",
			attestationType: AttestationTypeSEVSNP,
			report:          []byte{snpAttestTagSecureBootGCP},
			want:            "carries Secure Boot evidence",
		},
		{
			name:            "secure type reaches secure verifier",
			attestationType: AttestationTypeSecureBoot,
			report:          []byte{snpAttestTagSecureBootGCP},
			want:            "decode Secure Boot envelope",
		},
		{
			name:            "legacy type reaches legacy verifier",
			attestationType: AttestationTypeSEVSNP,
			report:          []byte{snpAttestTagGCP},
			want:            "decode SEV-SNP envelope",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := VerifyTypedSNPNonceAttestation(test.attestationType, test.report)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verification error = %v, want %q", err, test.want)
			}
		})
	}
}

// buildSecureBootEventLog returns a minimal TPM 2.0 event log whose only
// replayed event is a PCR 7 event with the given type, plus PCR values that
// replay cleanly for PCR 7.
func buildSecureBootEventLog(t *testing.T, eventType uint32, data []byte) ([]byte, map[uint32][]byte) {
	t.Helper()

	spec := new(bytes.Buffer)
	spec.WriteString("Spec ID Event03\x00")
	binary.Write(spec, binary.LittleEndian, uint32(0)) // platform class
	spec.Write([]byte{0, 2, 0, 2})                     // minor, major, errata, uintn size
	binary.Write(spec, binary.LittleEndian, uint32(1)) // algorithm count
	binary.Write(spec, binary.LittleEndian, uint16(0x000B))
	binary.Write(spec, binary.LittleEndian, uint16(sha256.Size))
	spec.Write([]byte{0}) // vendor info size

	var log bytes.Buffer
	binary.Write(&log, binary.LittleEndian, uint32(0)) // spec ID event: PCR 0
	binary.Write(&log, binary.LittleEndian, uint32(3)) // EV_NO_ACTION
	log.Write(make([]byte, 20))                        // unused SHA-1 digest
	binary.Write(&log, binary.LittleEndian, uint32(spec.Len()))
	log.Write(spec.Bytes())

	digest := sha256.Sum256(data)
	binary.Write(&log, binary.LittleEndian, uint32(7)) // PCR 7
	binary.Write(&log, binary.LittleEndian, eventType)
	binary.Write(&log, binary.LittleEndian, uint32(1)) // digest count
	binary.Write(&log, binary.LittleEndian, uint16(0x000B))
	log.Write(digest[:])
	binary.Write(&log, binary.LittleEndian, uint32(len(data)))
	log.Write(data)

	extend := sha256.New()
	extend.Write(make([]byte, sha256.Size))
	extend.Write(digest[:])
	pcrs := map[uint32][]byte{
		4:  make([]byte, sha256.Size),
		7:  extend.Sum(nil),
		11: make([]byte, sha256.Size),
	}
	return log.Bytes(), pcrs
}

// GO-2026-6893: the event type is a plain uint32 copied from the log and no
// digest covers it, so a host can put an arbitrary value there. A type the
// verifier does not recognise must be an error, never a panic.
func TestReleaseSecureBootEventLogRejectsUnknownEventType(t *testing.T) {
	eventLog, pcrs := buildSecureBootEventLog(t, 0x800000FF, []byte("event data"))

	_, err := verifyReleaseSecureBootEventLog(eventLog, pcrs, crypto.SHA256)
	if err == nil || !strings.Contains(err.Error(), "unrecognised event type") {
		t.Fatalf("verification error = %v, want it to report an unrecognised event type", err)
	}
}

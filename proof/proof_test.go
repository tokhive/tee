package proof

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// testEpoch is a stand-in for a real attested key epoch. It exercises the same
// platform.Signature and platform.VerifySignature path production uses, so the
// tests cover the real signature binding rather than a stubbed one.
type testEpoch struct {
	key      *ecdsa.PrivateKey
	identity platform.Identity
}

func newTestEpoch(t *testing.T) *testEpoch {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	evidence := []byte("pretend-sev-snp-report")

	return &testEpoch{
		key: key,
		identity: platform.Identity{
			Platform:        platform.PlatformAWSSEVSNP,
			AttestationType: "sev-snp",
			ApplicationID:   "tokenhive-tee-v1",
			Evidence:        evidence,
			EvidenceHash:    sha256.Sum256(evidence),
			PublicKeyDER:    publicKeyDER,
			KeyID:           sha256.Sum256(publicKeyDER),
		},
	}
}

func (e *testEpoch) Identity() platform.Identity { return platform.CloneIdentity(e.identity) }

func (e *testEpoch) Sign(domain string, payload []byte) (platform.Signature, error) {
	digest, err := platform.SigningDigest(domain, payload)
	if err != nil {
		return platform.Signature{}, err
	}
	value, err := ecdsa.SignASN1(rand.Reader, e.key, digest[:])
	if err != nil {
		return platform.Signature{}, err
	}
	return platform.Signature{
		Algorithm: platform.SignatureAlgorithmECDSAP256SHA256ASN1,
		KeyID:     e.identity.KeyID,
		Value:     value,
	}, nil
}

func testReceipt(t *testing.T) Receipt {
	t.Helper()

	jobID := make([]byte, JobIDLength)
	specHash := sha256.Sum256([]byte("job spec"))
	streamHash := sha256.Sum256([]byte("response"))

	return Receipt{
		Version:       VersionV1,
		JobID:         jobID,
		JobSpecHash:   specHash[:],
		Provider:      "openai",
		Method:        "POST",
		Host:          "api.openai.com",
		Path:          "/v1/responses",
		StatusCode:    200,
		StreamHash:    streamHash[:],
		ChunkCount:    3,
		ResponseBytes: 512,
		Completion:    CompletionComplete,
		StartedAt:     time.Now().Add(-time.Second).Unix(),
		FinishedAt:    time.Now().Unix(),
	}
}

func signedTestReceipt(t *testing.T) (SignedReceipt, *testEpoch) {
	t.Helper()
	signer := NewSigner(newTestEpoch(t))
	signed, err := signer.Sign(testReceipt(t))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed, signer.epoch.(*testEpoch)
}

// --- Streaming hasher -------------------------------------------------------

func TestStreamingHasherMatchesWholeBodyDigest(t *testing.T) {
	jobID := []byte("0123456789abcdef")
	chunks := [][]byte{
		[]byte("data: "),
		[]byte(`{"delta":"he"}`),
		[]byte("\n\ndata: "),
		[]byte(`{"delta":"llo"}`),
		[]byte("\n\n"),
	}

	hasher := NewStreamingHasher(jobID)
	for _, chunk := range chunks {
		if err := hasher.WriteChunk(chunk); err != nil {
			t.Fatalf("write chunk: %v", err)
		}
	}

	incremental := hasher.Sum()
	whole := HashResponseStream(jobID, chunks)
	if incremental != whole {
		t.Fatalf("incremental %x != whole %x", incremental, whole)
	}

	// The digest must equal SHA-256 over the literal prefix, job ID, and
	// concatenated body — the definition the scheme promises verifiers.
	want := sha256.Sum256(append(append([]byte(ResponseStreamDomain), jobID...), concat(chunks)...))
	if incremental != want {
		t.Fatalf("got %x, want %x", incremental, want)
	}
}

func TestStreamingHasherIsFramingIndependent(t *testing.T) {
	jobID := []byte("job")
	body := []byte("abcdefghij")

	one := HashResponseStream(jobID, [][]byte{body})
	many := HashResponseStream(jobID, [][]byte{body[:3], body[3:7], body[7:]})

	if one != many {
		t.Fatal("re-chunking a response changed its digest")
	}
}

func TestStreamingHasherBindsJobID(t *testing.T) {
	body := [][]byte{[]byte("same body")}
	if HashResponseStream([]byte("job-a"), body) == HashResponseStream([]byte("job-b"), body) {
		t.Fatal("digest does not depend on the job ID")
	}
}

func TestStreamingHasherSumIsNonDestructive(t *testing.T) {
	hasher := NewStreamingHasher([]byte("job"))
	_ = hasher.WriteChunk([]byte("first"))

	checkpoint := hasher.Sum()
	if err := hasher.WriteChunk([]byte("second")); err != nil {
		t.Fatalf("write chunk: %v", err)
	}
	final := hasher.Sum()

	if checkpoint == final {
		t.Fatal("digest did not advance after more input")
	}
	if final != HashResponseStream([]byte("job"), [][]byte{[]byte("first"), []byte("second")}) {
		t.Fatal("checkpointing corrupted the digest")
	}
}

func TestStreamingHasherCounters(t *testing.T) {
	hasher := NewStreamingHasher([]byte("job"))
	if err := hasher.WriteChunk([]byte("abc")); err != nil {
		t.Fatalf("write chunk: %v", err)
	}
	if _, err := hasher.Write([]byte("de")); err != nil {
		t.Fatalf("write: %v", err)
	}

	if hasher.ChunkCount() != 1 {
		t.Errorf("chunk count = %d, want 1 (Write does not advance it)", hasher.ChunkCount())
	}
	if hasher.BytesWritten() != 5 {
		t.Errorf("bytes written = %d, want 5", hasher.BytesWritten())
	}
}

func TestStreamingHasherReset(t *testing.T) {
	hasher := NewStreamingHasher([]byte("job"))
	_ = hasher.WriteChunk([]byte("transient"))
	hasher.Reset()

	if hasher.ChunkCount() != 0 || hasher.BytesWritten() != 0 {
		t.Fatalf("reset left counters at %d/%d", hasher.ChunkCount(), hasher.BytesWritten())
	}
	_ = hasher.WriteChunk([]byte("fresh"))
	if hasher.Sum() != HashResponseStream([]byte("job"), [][]byte{[]byte("fresh")}) {
		t.Fatal("digest after reset is wrong; job binding lost")
	}
}

// --- Receipt validation -----------------------------------------------------

func TestValidateRejects(t *testing.T) {
	validAttestation := func() *AttestationRef {
		return &AttestationRef{
			Platform:        platform.PlatformAWSSEVSNP,
			AttestationType: "sev-snp",
			ApplicationID:   "tokenhive-tee-v1",
			KeyID:           digestOf([]byte("pk")),
			PublicKeyDER:    []byte("pk"),
			EvidenceHash:    digestOf([]byte("evidence")),
		}
	}

	tests := []struct {
		name string
		mut  func(*Receipt)
		want error
	}{
		{"bad version", func(r *Receipt) { r.Version = 2 }, ErrUnsupportedVersion},
		{"short job id", func(r *Receipt) { r.JobID = r.JobID[:8] }, ErrInvalidJobID},
		{"short spec hash", func(r *Receipt) { r.JobSpecHash = r.JobSpecHash[:16] }, ErrInvalidJobSpecHash},
		{"short stream hash", func(r *Receipt) { r.StreamHash = r.StreamHash[:16] }, ErrInvalidStreamHash},
		{"zero completion", func(r *Receipt) { r.Completion = CompletionUnspecified }, ErrInvalidCompletion},
		{"undefined completion", func(r *Receipt) { r.Completion = CompletionState(9) }, ErrInvalidCompletion},
		{"zero start", func(r *Receipt) { r.StartedAt = 0 }, ErrInvalidTimeRange},
		{"finish before start", func(r *Receipt) { r.FinishedAt = r.StartedAt - 1 }, ErrInvalidTimeRange},
		{"nil attestation", func(r *Receipt) { r.Attestation = nil }, ErrMissingAttestation},
		{
			"empty platform",
			func(r *Receipt) { r.Attestation = validAttestation(); r.Attestation.Platform = "" },
			ErrInvalidAttestation,
		},
		{
			"key id mismatch",
			func(r *Receipt) {
				r.Attestation = validAttestation()
				r.Attestation.KeyID = digestOf([]byte("other"))
			},
			ErrInvalidAttestation,
		},
		{
			"short evidence hash",
			func(r *Receipt) {
				r.Attestation = validAttestation()
				r.Attestation.EvidenceHash = r.Attestation.EvidenceHash[:8]
			},
			ErrInvalidAttestation,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			receipt := testReceipt(t)
			receipt.Attestation = validAttestation()
			tc.mut(&receipt)

			err := receipt.Validate()
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCompletionStateString(t *testing.T) {
	if got := CompletionComplete.String(); got != "complete" {
		t.Errorf("got %q, want complete", got)
	}
	if got := CompletionState(200).String(); got == "" {
		t.Error("undefined state should still render")
	}
}

// --- Signing and verification ----------------------------------------------

func TestSignAndVerifyRoundTrip(t *testing.T) {
	signed, _ := signedTestReceipt(t)

	if err := Verify(signed, VerifyOptions{}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignFillsAttestationFromEpoch(t *testing.T) {
	epoch := newTestEpoch(t)
	signed, err := NewSigner(epoch).Sign(testReceipt(t))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	attestation := signed.Receipt.Attestation
	if attestation == nil {
		t.Fatal("attestation not populated")
	}
	if attestation.Platform != platform.PlatformAWSSEVSNP {
		t.Errorf("platform = %q, want %q", attestation.Platform, platform.PlatformAWSSEVSNP)
	}
	if attestation.ApplicationID != epoch.identity.ApplicationID {
		t.Errorf("application ID = %q, want %q", attestation.ApplicationID, epoch.identity.ApplicationID)
	}
	wantEvidenceHash := sha256.Sum256(epoch.identity.Evidence)
	if !constantTimeEqual(attestation.EvidenceHash, wantEvidenceHash[:]) {
		t.Error("evidence hash does not match the epoch evidence")
	}
}

func TestSignRejectsCallerSuppliedAttestation(t *testing.T) {
	epoch := newTestEpoch(t)
	receipt := testReceipt(t)
	// A caller must not be able to make a receipt claim an identity the signing
	// key cannot back up.
	receipt.Attestation = &AttestationRef{
		Platform:        "totally-trusted",
		AttestationType: "none",
		ApplicationID:   "attacker",
		KeyID:           digestOf([]byte("attacker key")),
		PublicKeyDER:    []byte("attacker key"),
		EvidenceHash:    make([]byte, EvidenceHashLength),
	}

	signed, err := NewSigner(epoch).Sign(receipt)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if signed.Receipt.Attestation.Platform != platform.PlatformAWSSEVSNP {
		t.Fatal("caller-supplied attestation survived signing")
	}
	if err := Verify(signed, VerifyOptions{}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignRequiresEpoch(t *testing.T) {
	var signer *Signer
	if _, err := signer.Sign(testReceipt(t)); !errors.Is(err, ErrNoEpoch) {
		t.Fatalf("got %v, want %v", err, ErrNoEpoch)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	// Every field of the receipt is inside the signature, so mutating any of
	// them must break verification.
	mutations := map[string]func(*Receipt){
		"job id":         func(r *Receipt) { r.JobID[0] ^= 0xff },
		"job spec hash":  func(r *Receipt) { r.JobSpecHash[0] ^= 0xff },
		"provider":       func(r *Receipt) { r.Provider = "evil" },
		"method":         func(r *Receipt) { r.Method = "GET" },
		"host":           func(r *Receipt) { r.Host = "evil.example" },
		"path":           func(r *Receipt) { r.Path = "/admin" },
		"status code":    func(r *Receipt) { r.StatusCode = 500 },
		"stream hash":    func(r *Receipt) { r.StreamHash[0] ^= 0xff },
		"chunk count":    func(r *Receipt) { r.ChunkCount++ },
		"response bytes": func(r *Receipt) { r.ResponseBytes++ },
		"completion":     func(r *Receipt) { r.Completion = CompletionTruncated },
		"finished at":    func(r *Receipt) { r.FinishedAt++ },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			signed, _ := signedTestReceipt(t)
			mutate(&signed.Receipt)
			if err := Verify(signed, VerifyOptions{}); err == nil {
				t.Fatal("tampered receipt accepted")
			}
		})
	}
}

func TestVerifyRejectsForeignSignature(t *testing.T) {
	signed, _ := signedTestReceipt(t)
	other := newTestEpoch(t)

	// Re-sign the receipt body with an unattested key that the receipt does not
	// name.
	encoded, err := signed.Receipt.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	foreign, err := other.Sign(ReceiptSigningDomain, encoded)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signed.Signature = foreign

	err = Verify(signed, VerifyOptions{})
	if !errors.Is(err, ErrAttestationMismatch) {
		t.Fatalf("got %v, want %v", err, ErrAttestationMismatch)
	}
}

func TestVerifyRejectsSignatureFromAnotherDomain(t *testing.T) {
	signed, epoch := signedTestReceipt(t)

	encoded, err := signed.Receipt.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// A signature made for some other purpose must not be accepted here.
	wrongDomain, err := epoch.Sign("TokenHive.SomeOtherThing.v1", encoded)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signed.Signature = wrongDomain

	if err := Verify(signed, VerifyOptions{}); err == nil {
		t.Fatal("signature from a different domain accepted")
	}
}

func TestVerifyOptions(t *testing.T) {
	t.Run("platform allowlist", func(t *testing.T) {
		signed, _ := signedTestReceipt(t)

		allowed := VerifyOptions{AllowedPlatforms: []string{platform.PlatformAWSSEVSNP}}
		if err := Verify(signed, allowed); err != nil {
			t.Fatalf("allowlisted platform rejected: %v", err)
		}

		denied := VerifyOptions{AllowedPlatforms: []string{"gcp-confidential-space"}}
		err := Verify(signed, denied)
		if !errors.Is(err, ErrPlatformNotAllowed) {
			t.Fatalf("got %v, want %v", err, ErrPlatformNotAllowed)
		}
	})

	t.Run("require evidence", func(t *testing.T) {
		signed, _ := signedTestReceipt(t)
		// Default signers omit evidence to stay inside the size budget.
		err := Verify(signed, VerifyOptions{RequireEvidence: true})
		if !errors.Is(err, ErrEvidenceRequired) {
			t.Fatalf("got %v, want %v", err, ErrEvidenceRequired)
		}

		epoch := newTestEpoch(t)
		signer := NewSigner(epoch)
		signer.IncludeEvidence = true
		selfContained, err := signer.Sign(testReceipt(t))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if err := Verify(selfContained, VerifyOptions{RequireEvidence: true}); err != nil {
			t.Fatalf("self-contained receipt rejected: %v", err)
		}
	})

	t.Run("max age", func(t *testing.T) {
		receipt := testReceipt(t)
		now := time.Unix(receipt.FinishedAt, 0)
		signed, err := NewSigner(newTestEpoch(t)).Sign(receipt)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}

		fresh := VerifyOptions{Now: now, MaxAge: time.Hour}
		if err := Verify(signed, fresh); err != nil {
			t.Fatalf("fresh receipt rejected: %v", err)
		}

		stale := VerifyOptions{Now: now.Add(2 * time.Hour), MaxAge: time.Hour}
		err = Verify(signed, stale)
		if !errors.Is(err, ErrReceiptTooOld) {
			t.Fatalf("got %v, want %v", err, ErrReceiptTooOld)
		}
	})
}

func TestDecodeAndVerify(t *testing.T) {
	signed, _ := signedTestReceipt(t)
	encoded, err := signed.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, err := DecodeAndVerify(encoded, VerifyOptions{})
	if err != nil {
		t.Fatalf("decode and verify: %v", err)
	}
	if decoded.Receipt.StatusCode != signed.Receipt.StatusCode {
		t.Fatalf("status = %d, want %d", decoded.Receipt.StatusCode, signed.Receipt.StatusCode)
	}
}

func TestDecodeAndVerifyRejectsNonCanonicalBytes(t *testing.T) {
	signed, _ := signedTestReceipt(t)
	encoded, err := signed.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Flip a byte inside the receipt body. Even if the result still decodes,
	// verification must fail.
	corrupted := append([]byte(nil), encoded...)
	corrupted[len(corrupted)/2] ^= 0xff
	if _, err := DecodeAndVerify(corrupted, VerifyOptions{}); err == nil {
		t.Fatal("corrupted encoding accepted")
	}
}

func TestMatchesStream(t *testing.T) {
	jobID := make([]byte, JobIDLength)
	chunks := [][]byte{[]byte("data: "), []byte(`{"delta":"hi"}`), []byte("\n\n")}

	receipt := testReceipt(t)
	streamHash := HashResponseStream(jobID, chunks)
	receipt.StreamHash = streamHash[:]

	if !receipt.MatchesStream(chunks) {
		t.Fatal("matching transcript rejected")
	}
	if receipt.MatchesStream([][]byte{[]byte("different")}) {
		t.Fatal("mismatched transcript accepted")
	}
}

func TestReceiptSizeBudget(t *testing.T) {
	signed, _ := signedTestReceipt(t)
	encoded, err := signed.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// The roadmap caps an attestation-bearing receipt at 2KB. Without inline
	// evidence it should land far under that, leaving room for longer paths and
	// provider names.
	const budget = 2048
	if len(encoded) > budget {
		t.Errorf("signed receipt is %d bytes, over the %d byte budget", len(encoded), budget)
	}
	t.Logf("signed receipt size: %d bytes", len(encoded))
}

func concat(chunks [][]byte) []byte {
	var out []byte
	for _, chunk := range chunks {
		out = append(out, chunk...)
	}
	return out
}

// digestOf returns the SHA-256 of b as a slice, which is the shape the
// attestation reference fields use.
func digestOf(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

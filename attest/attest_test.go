package attest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/sevsnp"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// testSigner is a signer plus the whitelist digest its epoch was configured
// with. A receipt must name the policy its enclave enforced, so the fixture that
// builds receipts has to know which one that was.
type testSigner struct {
	*proof.Signer
	policy [32]byte
}

// makeSigner returns a signer bound to a fresh simulated epoch, plus the epoch's
// public identity for populating an evidence cache.
func makeSigner(t *testing.T, bound [32]byte) (testSigner, platform.Identity) {
	t.Helper()
	var e platform.Epoch
	var err error
	if bound != [32]byte{} {
		e, err = simulated.NewDeploymentEpoch(bound)
	} else {
		e, err = simulated.NewEpoch()
	}
	if err != nil {
		t.Fatalf("new epoch: %v", err)
	}
	return testSigner{Signer: proof.NewSigner(e), policy: bound}, e.Identity()
}

// makeReceipt signs a minimal-but-structurally-valid receipt so the signature
// and structural checks in Check run against a real receipt.
func makeReceipt(t *testing.T, signer testSigner) proof.SignedReceipt {
	t.Helper()
	jobID := make([]byte, proof.JobIDLength)
	_, _ = rand.Read(jobID)
	specHash := make([]byte, proof.JobSpecHashLength)
	streamHash := make([]byte, proof.StreamHashLength)
	now := time.Now().Unix()
	receipt := proof.Receipt{
		Version:       proof.VersionV1,
		JobID:         jobID,
		JobSpecHash:   specHash,
		Provider:      "openai-sim",
		Method:        "POST",
		Host:          "127.0.0.1:18080",
		Path:          "/v1/chat/completions",
		StatusCode:    200,
		StreamHash:    streamHash,
		ChunkCount:    1,
		ResponseBytes: 0,
		Completion:    proof.CompletionComplete,
		StartedAt:     now,
		FinishedAt:    now,
		RequestBytes:  0,
		ProviderSeq:   1,
		// The whitelist the signing enclave was configured with: a receipt that
		// did not name it would not be a proof of what the enclave enforced.
		PolicyHash: signer.policy[:],
	}
	signed, err := signer.Sign(receipt)
	if err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	return signed
}

func defaultConfig(t *testing.T, fetcher Fetcher, policyHash [32]byte) *Verifier {
	t.Helper()
	cfg := Config{
		AllowedPlatforms: []string{simulated.Platform},
		ByPlatform:       map[string]platform.EvidenceVerifier{simulated.Platform: simulated.Verifier{}},
		Fetcher:          fetcher,
		PolicyHash:       policyHash,
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return v
}

func TestAllowlistRefusesDisallowedPlatform(t *testing.T) {
	signer, _ := makeSigner(t, [32]byte{})
	signed := makeReceipt(t, signer)

	// A trust root that accepts only the real AWS SEV-SNP platform must refuse
	// a simulated receipt, even though the simulated verifier is registered.
	v, err := New(Config{
		AllowedPlatforms: []string{platform.PlatformAWSSEVSNP},
		ByPlatform: map[string]platform.EvidenceVerifier{
			simulated.Platform:         simulated.Verifier{},
			platform.PlatformAWSSEVSNP: sevsnp.Verifier{},
		},
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := v.Check(signed); !errors.Is(err, proof.ErrPlatformNotAllowed) {
		t.Fatalf("Check = %v, want ErrPlatformNotAllowed", err)
	}
}

func TestNewRejectsEmptyAllowlist(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New accepted an empty AllowedPlatforms")
	}
}

func TestNewRejectsAllowedPlatformWithoutVerifier(t *testing.T) {
	_, err := New(Config{
		AllowedPlatforms: []string{"aws-sev-snp"},
		ByPlatform:       map[string]platform.EvidenceVerifier{},
	})
	if err == nil {
		t.Fatal("New accepted an allowed platform with no verifier")
	}
}

func TestInlineEvidenceVerifies(t *testing.T) {
	// IncludeEvidence=true signs a self-contained receipt; with no Fetcher the
	// verifier must demand inline evidence and accept the sim trust root.
	signer, _ := makeSigner(t, [32]byte{})
	signer.IncludeEvidence = true
	signed := makeReceipt(t, signer)

	v := defaultConfig(t, nil, [32]byte{})
	if err := v.Check(signed); err != nil {
		t.Fatalf("Check(tampered) = %v, want nil", err)
	}
}

func TestInlineEvidenceTamperedFails(t *testing.T) {
	signer, _ := makeSigner(t, [32]byte{})
	signer.IncludeEvidence = true
	signed := makeReceipt(t, signer)
	// Flip one byte in the receipt body — signature must no longer verify.
	signed.Receipt.ResponseBytes++

	v := defaultConfig(t, nil, [32]byte{})
	if err := v.Check(signed); err == nil {
		t.Fatal("Check accepted a tampered receipt")
	}
}

func TestHashOnlyReceiptResolvesViaFetcher(t *testing.T) {
	signer, identity := makeSigner(t, [32]byte{})
	// A small, hash-only receipt (IncludeEvidence=false is the Signer default).
	signed := makeReceipt(t, signer)
	if len(signed.Receipt.Attestation.Evidence) != 0 {
		t.Fatal("expected a hash-only receipt")
	}

	// The verifier resolves the hash through whatever the deployment filled when
	// it saw the TEE come online — its local store, a peer's endpoint, anything.
	// This is that seam.
	v := defaultConfig(t, FuncFetcher(func(_ context.Context, id platform.Identity) ([]byte, error) {
		if id.EvidenceHash != identity.EvidenceHash {
			return nil, errors.New("no evidence for that hash")
		}
		return identity.Evidence, nil
	}), [32]byte{})
	if err := v.Check(signed); err != nil {
		t.Fatalf("Check(hash-only) = %v, want nil", err)
	}
}

func TestHashOnlyReceiptWithoutFetcherFails(t *testing.T) {
	signer, _ := makeSigner(t, [32]byte{})
	signed := makeReceipt(t, signer)

	v := defaultConfig(t, nil, [32]byte{})
	if err := v.Check(signed); !errors.Is(err, proof.ErrEvidenceRequired) {
		t.Fatalf("Check = %v, want ErrEvidenceRequired", err)
	}
}

func TestWrongEvidenceFromFetcherFails(t *testing.T) {
	signer, _ := makeSigner(t, [32]byte{})
	signed := makeReceipt(t, signer)

	// A fetcher that returns bytes whose hash does not match the receipt's
	// EvidenceHash must be refused by the simulated platform's evidence check.
	v := defaultConfig(t, FuncFetcher(func(ctx context.Context, id platform.Identity) ([]byte, error) {
		return []byte("wrong-evidence"), nil
	}), [32]byte{})
	if err := v.Check(signed); err == nil {
		t.Fatal("Check accepted evidence with a hash mismatch")
	}
}

func TestDeploymentBindingEnforced(t *testing.T) {
	policyHash := sha256Of([]byte("deployment-policy-set"))

	cfg := Config{
		AllowedPlatforms: []string{simulated.Platform},
		ByPlatform:       map[string]platform.EvidenceVerifier{simulated.Platform: simulated.Verifier{}},
		PolicyHash:       policyHash,
	}
	deployVer, err := New(cfg)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	// Enclave configured with the expected policy set: binds cleanly.
	boundSigner, _ := makeSigner(t, policyHash)
	boundSigner.IncludeEvidence = true // self-contained, no Fetcher dependency
	if err := deployVer.Check(makeReceipt(t, boundSigner)); err != nil {
		t.Fatalf("Check(deployment-bound, matching) = %v, want nil", err)
	}

	// Same enclave image but an epoch never bound to a policy set must be
	// refused, because its evidence cannot show the required configuration.
	looseSigner, _ := makeSigner(t, [32]byte{})
	looseSigner.IncludeEvidence = true
	if err := deployVer.Check(makeReceipt(t, looseSigner)); err == nil {
		t.Fatal("Check accepted an unbound receipt against a deployment-bound verifier")
	}

	// An enclave configured with the pinned policy, signing a receipt that names
	// another one. The signature is genuine and the evidence is bound, so this
	// is caught only by comparing the receipt's own statement of its whitelist —
	// which is the assertion that makes the policy part of the execution proof.
	misnamed := makeReceipt(t, testSigner{
		Signer: boundSigner.Signer,
		policy: sha256Of([]byte("some other whitelist")),
	})
	if err := deployVer.Check(misnamed); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("Check(receipt naming another policy) = %v, want %v", err, ErrPolicyMismatch)
	}
}

func sha256Of(b []byte) [32]byte { return sha256.Sum256(b) }

package tee

import (
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// TestSimReceiptWithinBudget is the permanent, network-free gate for the §9
// proof-volume budget: a self-contained simulated receipt (IncludeEvidence=true,
// exactly what cmd/tee emits) must stay under 2 KiB. The plan is explicit that
// the sim adapter must satisfy this and it is non-negotiable; a real SEV-SNP
// report is several KB and is deliberately kept out of the receipt (production
// sets IncludeEvidence=false and resolves EvidenceHash from a cache).
func TestSimReceiptWithinBudget(t *testing.T) {
	epoch, err := simulated.NewEpoch()
	if err != nil {
		t.Fatalf("new epoch: %v", err)
	}
	signer := proof.NewSigner(epoch)
	signer.IncludeEvidence = true // mirrors cmd/tee, the worst case for size

	now := time.Now()
	receipt := proof.Receipt{
		Version:       proof.VersionV1,
		JobID:         make([]byte, proof.JobIDLength),
		JobSpecHash:   make([]byte, 32),
		Provider:      "openai-sim",
		Method:        "POST",
		Host:          "127.0.0.1:18080",
		Path:          "/v1/chat/completions",
		StatusCode:    200,
		StreamHash:    make([]byte, 32),
		ChunkCount:    4,
		ResponseBytes: 312,
		Completion:    proof.CompletionComplete,
		StartedAt:     now.Unix(),
		FinishedAt:    now.Add(time.Second).Unix(),
		PolicyHash:    make([]byte, 32),
		RequestBytes:  128,
		ProviderSeq:   1,
	}

	signed, err := signer.Sign(receipt)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := signed.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(raw) >= 2048 {
		t.Fatalf("sim receipt is %d bytes; §9 budget is < 2048 (self-contained sim receipts must fit)", len(raw))
	}
	t.Logf("sim receipt size (IncludeEvidence=true): %d bytes", len(raw))

	// Receipt generation must be cheap: §9 p95 target is < 5ms. Measure the
	// dominant cost (one signing) and require it well under that.
	start := time.Now()
	if _, err := signer.Sign(receipt); err != nil {
		t.Fatalf("sign (timing): %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Millisecond {
		t.Fatalf("receipt signing took %v; §9 p95 target is < 5ms", elapsed)
	}
}

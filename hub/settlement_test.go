package hub

import (
	"context"
	"errors"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// TestSettlementRefusesSameJobTwice pins the dedup guard: one JobID settles
// exactly once, so a second Execute carrying the same job must not book a
// second charge. The second receipt carries a fresh ProviderSeq so it passes
// the receipt store's per-sequence dedup and reaches the settlement dedup —
// the exact replay a broken caller or double-charge attempt produces.
func TestSettlementRefusesSameJobTwice(t *testing.T) {
	stream := chunks("hello")
	spec := testSpec(testProvider, "m")
	spec.JobID = []byte("0123456789abcdef")
	receipts := []proof.SignedReceipt{
		makeReceipt(1, stream, func(r *proof.Receipt) { r.JobID = spec.JobID }),
		makeReceipt(2, stream, func(r *proof.Receipt) { r.JobID = spec.JobID }),
	}
	tee := &ScriptedTEE{Reply: func(call int, s jobs.Spec) (Result, error) {
		return Result{Status: 200, Headers: map[string][]string{}, Chunks: stream, Receipt: receipts[call-1]}, nil
	}}
	h := mustHub(t, Config{TEE: tee})

	first, err := h.Execute(context.Background(), "tenant", "m", spec, nil, nil)
	if err != nil {
		t.Fatalf("first settlement: %v", err)
	}
	if !first.Stored {
		t.Fatal("first settlement did not store its receipt")
	}

	if _, err := h.Execute(context.Background(), "tenant", "m", spec, nil, nil); !errors.Is(err, ErrDuplicateSettlement) {
		t.Fatalf("second settlement err = %v, want ErrDuplicateSettlement", err)
	}
	snap := h.Ledger().Snapshot()
	if snap.Settled != 1 {
		t.Fatalf("settled = %d, want exactly 1 (the repeat must not book)", snap.Settled)
	}
}

// TestClaimSettlementDistinguishesJobs makes sure the dedup key is the JobID,
// not a coarse counter: two distinct jobs both settle.
func TestClaimSettlementDistinguishesJobs(t *testing.T) {
	h := mustHub(t, Config{TEE: &ScriptedTEE{Reply: func(int, jobs.Spec) (Result, error) { return Result{}, nil }}})
	if !h.claimSettlement([]byte("job-a")) {
		t.Fatal("first claim of job-a refused")
	}
	if h.claimSettlement([]byte("job-a")) {
		t.Fatal("second claim of job-a admitted")
	}
	if !h.claimSettlement([]byte("job-b")) {
		t.Fatal("claim of a distinct job refused")
	}
}

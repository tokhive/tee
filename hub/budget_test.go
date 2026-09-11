package hub

import (
	"context"
	"errors"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

// The budget is the cumulative counterpart of MaxJobMicros: the ceiling bounds
// one job, the budget bounds the sum. These tests pin both halves — that an
// exhausted tenant is refused before dispatch, and that only settled money is
// counted against it.

func TestBudgetRefusesOnlyWhatIsProvisioned(t *testing.T) {
	b, err := NewBudget(map[string]uint64{"alice": 100})
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	if !b.Allow("bob") {
		t.Fatalf("a tenant with no provisioned budget must be admitted")
	}
	if _, ok := b.Remaining("bob"); ok {
		t.Fatalf("an unprovisioned tenant must report no budget")
	}
	b.Record("bob", 1<<40) // must be a no-op, not a tracked entry
	if !b.Allow("bob") {
		t.Fatalf("recording for an unprovisioned tenant must not cap it")
	}
	if _, ok := b.Remaining("bob"); ok {
		t.Fatalf("an unprovisioned tenant must stay untracked")
	}
}

func TestBudgetExhaustsAtTheCeiling(t *testing.T) {
	b, err := NewBudget(map[string]uint64{"alice": 100})
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	if !b.Allow("alice") {
		t.Fatalf("a fresh tenant must be admitted")
	}
	b.Record("alice", 60)
	if left, _ := b.Remaining("alice"); left != 40 {
		t.Fatalf("remaining = %d, want 40", left)
	}
	if !b.Allow("alice") {
		t.Fatalf("40 left must still admit a job (the charge is only known after it runs)")
	}
	b.Record("alice", 40)
	if b.Allow("alice") {
		t.Fatalf("an exhausted tenant must be refused")
	}
	if left, _ := b.Remaining("alice"); left != 0 {
		t.Fatalf("remaining = %d, want 0 at the ceiling", left)
	}
	// Overshooting must not wrap the total back to a small number, which would
	// hand the tenant its whole budget again.
	b.Record("alice", 1)
	if b.Allow("alice") {
		t.Fatalf("an over-ceiling tenant must stay refused")
	}
}

func TestNewBudgetRejectsMeaninglessCeilings(t *testing.T) {
	if _, err := NewBudget(nil); !errors.Is(err, ErrInvalidBudget) {
		t.Errorf("empty table error = %v, want ErrInvalidBudget", err)
	}
	if _, err := NewBudget(map[string]uint64{"": 1}); !errors.Is(err, ErrInvalidBudget) {
		t.Errorf("empty tenant error = %v, want ErrInvalidBudget", err)
	}
	if _, err := NewBudget(map[string]uint64{"alice": 0}); !errors.Is(err, ErrInvalidBudget) {
		t.Errorf("zero ceiling error = %v, want ErrInvalidBudget", err)
	}
}

func TestBudgetBlocksBeforeDispatch(t *testing.T) {
	stream := chunks("hello")
	fake := &ScriptedTEE{Reply: func(call int, _ jobs.Spec) (Result, error) {
		return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, nil)}, nil
	}}
	// Exactly one job's worth: the first fits, the second has nothing left.
	h := mustHub(t, Config{
		TEE:     fake,
		Rates:   ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 1_000_000}}),
		Budgets: map[string]uint64{"tenant": 1_000_000},
	})

	first, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	if first.Buyer != 1_000_000 {
		t.Fatalf("buyer = %d, want 1000000", first.Buyer)
	}
	if left, _ := h.budget.Remaining("tenant"); left != 0 {
		t.Fatalf("remaining after one job = %d, want 0", left)
	}

	_, err = h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil)
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("second request error = %v, want ErrBudgetExceeded", err)
	}
	// Refused before dispatch, exactly as the quota is: a job the buyer cannot
	// pay for must never spend the provider's credential or a ProviderSeq.
	if fake.Calls() != 1 {
		t.Errorf("TEE calls = %d, want 1: the budget must block before dispatch", fake.Calls())
	}
}

// TestBudgetOvershootsByOneJobAtMost pins the known limit of check-then-record:
// the charge is only known after the job is priced, so a tenant just under its
// ceiling is admitted and can land one job past it. The bound is one job, which
// is what MaxJobMicros makes finite — it is a documented overshoot, not an
// unbounded one.
func TestBudgetOvershootsByOneJobAtMost(t *testing.T) {
	stream := chunks("hello")
	fake := &ScriptedTEE{Reply: func(call int, _ jobs.Spec) (Result, error) {
		return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, nil)}, nil
	}}
	h := mustHub(t, Config{
		TEE:     fake,
		Rates:   ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 1_000_000}}),
		Budgets: map[string]uint64{"tenant": 1_500_000},
	})
	ctx := context.Background()

	// Used 0 < 1.5M: admitted, taking the total to 1M.
	if _, err := h.Execute(ctx, "tenant", "m", testSpec(testProvider, "m"), nil, nil); err != nil {
		t.Fatalf("first request: %v", err)
	}
	// Used 1M < 1.5M: still admitted, taking the total to 2M — one job past.
	if _, err := h.Execute(ctx, "tenant", "m", testSpec(testProvider, "m"), nil, nil); err != nil {
		t.Fatalf("second request: %v (a job under the ceiling must be admitted)", err)
	}
	// Used 2M >= 1.5M: the overshoot is spent, so the next job is refused.
	if _, err := h.Execute(ctx, "tenant", "m", testSpec(testProvider, "m"), nil, nil); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("third request error = %v, want ErrBudgetExceeded", err)
	}
	if fake.Calls() != 2 {
		t.Errorf("TEE calls = %d, want 2: the overshoot must be bounded at one job", fake.Calls())
	}
}

func TestBudgetIgnoresJobsThatSettleNothing(t *testing.T) {
	stream := chunks("hello")
	fake := &ScriptedTEE{Reply: func(call int, _ jobs.Spec) (Result, error) {
		return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, nil)}, nil
	}}
	// A per-job ceiling far below what the card prices: the job runs, its
	// receipt is kept, and nothing is charged. Budget must not be consumed by a
	// refusal, or a buyer would lose budget to jobs it was never billed for.
	h := mustHub(t, Config{
		TEE:          fake,
		Rates:        ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 1_000_000}}),
		Budgets:      map[string]uint64{"tenant": 5_000_000},
		MaxJobMicros: 1,
	})

	if _, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil); !errors.Is(err, ErrJobPriceExceeded) {
		t.Fatalf("err = %v, want ErrJobPriceExceeded", err)
	}
	if left, _ := h.budget.Remaining("tenant"); left != 5_000_000 {
		t.Fatalf("remaining = %d, want the ceiling untouched by a refused job", left)
	}
}

func TestBudgetIsPerTenant(t *testing.T) {
	stream := chunks("hello")
	fake := &ScriptedTEE{Reply: func(call int, _ jobs.Spec) (Result, error) {
		return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, nil)}, nil
	}}
	h := mustHub(t, Config{
		TEE:     fake,
		Rates:   ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 1_000_000}}),
		Budgets: map[string]uint64{"alice": 1_000_000},
	})

	if _, err := h.Execute(context.Background(), "alice", "m", testSpec(testProvider, "m"), nil, nil); err != nil {
		t.Fatalf("alice first: %v", err)
	}
	if _, err := h.Execute(context.Background(), "alice", "m", testSpec(testProvider, "m"), nil, nil); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("alice second error = %v, want ErrBudgetExceeded", err)
	}
	// bob has no provisioned ceiling; alice's exhaustion must not touch him.
	if _, err := h.Execute(context.Background(), "bob", "m", testSpec(testProvider, "m"), nil, nil); err != nil {
		t.Fatalf("bob: %v", err)
	}
}

// TestBudgetBlocksSessionsBeforeOpen covers the streaming path: a session is a
// purchase too, so an exhausted tenant must be refused before the TEE is asked
// to open a tunnel to a provider.
func TestBudgetBlocksSessionsBeforeOpen(t *testing.T) {
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			return &scriptTunnel{rec: sessionReceipt(spec.JobID, 0, nil, 101)}, nil
		},
	}
	h := mustHub(t, Config{
		TEE:     fake,
		Rates:   ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 1_000_000}}),
		Budgets: map[string]uint64{"tenant": 1_000_000},
	})
	h.budget.Record("tenant", 1_000_000) // spend the whole ceiling

	if _, _, err := h.OpenSessionForModel(context.Background(), "tenant", "m", buildSession); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("err = %v, want ErrBudgetExceeded", err)
	}
	if fake.OpenCalls() != 0 {
		t.Fatalf("session opened %d times despite an exhausted budget, want 0", fake.OpenCalls())
	}
}

package hub

import (
	"context"
	"errors"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// These tests exercise the C2 business rules — lowest-price scheduling and the
// commission — against a scripted TEE, so the ordering and settling logic is
// verifiable in milliseconds with no network and no real credential.

// cardReply builds a receipt for a completed request under a provider's card.
func cardReply(call int, spec jobs.Spec, micros uint64, fail bool) (Result, error) {
	stream := chunks("ok")
	r := makeReceipt(uint64(call), stream, func(r *proof.Receipt) {
		r.Provider = spec.Provider
		r.ResponseBytes = uint64(len(stream[0]))
	})
	if fail {
		return Result{Chunks: stream, Receipt: r}, errors.New("transport failed")
	}
	return Result{Chunks: stream, Receipt: r}, nil
}

func buildFor(provider string) (jobs.Spec, error) {
	return testSpec(provider, "m"), nil
}

func scheduleHub(t *testing.T, rates map[string]RateCard, commission uint64) *Hub {
	t.Helper()
	h, err := New(Config{
		TEE:        &ScriptedTEE{Reply: func(int, jobs.Spec) (Result, error) { return Result{}, nil }},
		Rates:      rates,
		Store:      NewReceiptStore(t.TempDir()),
		Verify:     acceptAll,
		Commission: commission,
	})
	if err != nil {
		t.Fatalf("build hub: %v", err)
	}
	return h
}

func TestRankedProvidersOrdersByEffectivePrice(t *testing.T) {
	set := ratesTable(map[string]RateCard{
		// Effective price for model "m": PerRequest + Premium.
		"mid":   {PerRequestMicros: 500, ModelPremiumMicros: map[string]uint64{"m": 50}},  // 550
		"dear":  {PerRequestMicros: 900},                                                  // 900
		"cheap": {PerRequestMicros: 100},                                                  // 100
		"large": {PerRequestMicros: 200, ModelPremiumMicros: map[string]uint64{"m": 300}}, // 500
	})
	h := scheduleHub(t, set, 0)

	got := h.providersForModel("m")
	want := []string{"cheap", "large", "mid", "dear"}
	if len(got) != len(want) {
		t.Fatalf("ranked = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ranked[%d] = %q, want %q (order %v)", i, got[i], want[i], got)
		}
	}
}

func TestExecuteForModelPicksCheapestProvider(t *testing.T) {
	set := ratesTable(map[string]RateCard{
		"dear":  {PerRequestMicros: 900},
		"cheap": {PerRequestMicros: 100},
	})
	fake := &ScriptedTEE{Reply: func(call int, spec jobs.Spec) (Result, error) {
		return cardReply(call, spec, 100, false)
	}}
	h, _ := New(Config{TEE: fake, Rates: set, Store: NewReceiptStore(t.TempDir()), Verify: acceptAll})

	out, err := h.ExecuteForModel(context.Background(), "tenant", "m", nil, buildFor, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := out.Receipt.Receipt.Provider; got != "cheap" {
		t.Fatalf("chosen provider = %q, want %q (cheapest must serve first)", got, "cheap")
	}
	if out.Charged != 100 {
		t.Errorf("charged = %d, want 100", out.Charged)
	}
	if fake.Calls() != 1 {
		t.Errorf("TEE calls = %d, want 1", fake.Calls())
	}
}

func TestExecuteForModelFallsBackFromFailingCheapest(t *testing.T) {
	set := ratesTable(map[string]RateCard{
		"cheap": {PerRequestMicros: 100},
		"dear":  {PerRequestMicros: 900},
	})
	fake := &ScriptedTEE{Reply: func(call int, spec jobs.Spec) (Result, error) {
		if spec.Provider == "cheap" {
			return cardReply(call, spec, 0, true)
		}
		return cardReply(call, spec, 900, false)
	}}
	h, _ := New(Config{TEE: fake, Rates: set, Store: NewReceiptStore(t.TempDir()), Verify: acceptAll})

	out, err := h.ExecuteForModel(context.Background(), "tenant", "m", nil, buildFor, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := out.Receipt.Receipt.Provider; got != "dear" {
		t.Fatalf("chosen provider = %q, want %q (fallback must reach the next cheapest)", got, "dear")
	}
	if out.Charged != 900 {
		t.Errorf("charged = %d, want 900", out.Charged)
	}
	if fake.Calls() != 2 {
		t.Errorf("TEE calls = %d, want 2 (cheap then dear)", fake.Calls())
	}
}

func TestExecuteForModelCommitsAfterFirstRelayedByte(t *testing.T) {
	// The cheapest provider streams one chunk then truncates. Its bytes already
	// reached the user, so the Hub must NOT fall back to the next provider:
	// splicing a second provider's transcript onto the first would corrupt the
	// user's stream and match no single receipt.
	set := ratesTable(map[string]RateCard{
		"cheap": {PerRequestMicros: 100},
		"dear":  {PerRequestMicros: 900},
	})
	fake := &ScriptedTEE{Reply: func(call int, spec jobs.Spec) (Result, error) {
		stream := chunks("partial")
		if spec.Provider == "cheap" {
			r := makeReceipt(uint64(call), stream, func(r *proof.Receipt) {
				r.Provider = spec.Provider
				r.Completion = proof.CompletionTruncated
			})
			return Result{Chunks: stream, Receipt: r}, nil
		}
		// The dear provider would have completed fine — the test's point is
		// that it must never be asked once cheap's bytes are on the wire.
		return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, func(r *proof.Receipt) {
			r.Provider = spec.Provider
		})}, nil
	}}
	h, _ := New(Config{TEE: fake, Rates: set, Store: NewReceiptStore(t.TempDir()), Verify: acceptAll})

	var relayed int
	out, err := h.ExecuteForModel(context.Background(), "tenant", "m", nil, buildFor, func([]byte) error {
		relayed++
		return nil
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := out.Receipt.Receipt.Provider; got != "cheap" {
		t.Fatalf("chosen provider = %q, want %q (committed once bytes relayed)", got, "cheap")
	}
	if out.Receipt.Receipt.Completion != proof.CompletionTruncated {
		t.Fatalf("completion = %v, want truncated (the committed outcome is the partial one)", out.Receipt.Receipt.Completion)
	}
	if relayed != 1 {
		t.Errorf("user saw %d chunks, want exactly 1 (no second provider's bytes may follow)", relayed)
	}
	if fake.Calls() != 1 {
		t.Errorf("TEE calls = %d, want 1 (dear must not be tried after cheap relayed bytes)", fake.Calls())
	}
}

func TestExecuteForModelFallsBackFromNonBillableCheapest(t *testing.T) {
	set := ratesTable(map[string]RateCard{
		"cheap": {PerRequestMicros: 100},
		"dear":  {PerRequestMicros: 900},
	})
	fake := &ScriptedTEE{Reply: func(call int, spec jobs.Spec) (Result, error) {
		stream := chunks("")
		if spec.Provider == "cheap" {
			r := makeReceipt(uint64(call), stream, func(r *proof.Receipt) {
				r.Provider = spec.Provider
				r.StatusCode = 401
				r.Completion = proof.CompletionComplete
			})
			return Result{Chunks: stream, Receipt: r}, nil
		}
		return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, func(r *proof.Receipt) {
			r.Provider = spec.Provider
		})}, nil
	}}
	h, _ := New(Config{TEE: fake, Rates: set, Store: NewReceiptStore(t.TempDir()), Verify: acceptAll})

	out, err := h.ExecuteForModel(context.Background(), "tenant", "m", nil, buildFor, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := out.Receipt.Receipt.Provider; got != "dear" {
		t.Fatalf("chosen provider = %q, want %q (non-billable must fall back)", got, "dear")
	}
	if fake.Calls() != 2 {
		t.Errorf("TEE calls = %d, want 2", fake.Calls())
	}
}

func TestExecuteForModelNoProviders(t *testing.T) {
	set := ratesTable(map[string]RateCard{})
	h, _ := New(Config{TEE: &ScriptedTEE{}, Rates: set, Store: NewReceiptStore(t.TempDir()), Verify: acceptAll})
	_, err := h.ExecuteForModel(context.Background(), "tenant", "m", nil, buildFor, nil)
	if !errors.Is(err, ErrNoProviderForModel) {
		t.Fatalf("error = %v, want ErrNoProviderForModel", err)
	}
}

// --- commission -----------------------------------------------------------

func TestCommissionAddsToBuyerAndLedger(t *testing.T) {
	set := ratesTable(map[string]RateCard{
		"cheap": {PerRequestMicros: 1000},
	})
	fake := &ScriptedTEE{Reply: func(call int, spec jobs.Spec) (Result, error) {
		return cardReply(call, spec, 1000, false)
	}}
	h, _ := New(Config{
		TEE:        fake,
		Rates:      set,
		Store:      NewReceiptStore(t.TempDir()),
		Verify:     acceptAll,
		Commission: 1000, // 10%
	})
	out, err := h.ExecuteForModel(context.Background(), "tenant", "m", nil, buildFor, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	// seller 1000, commission = 1000*1000/10000 = 100, buyer = 1100.
	if out.Charged != 1000 {
		t.Errorf("charged = %d, want 1000", out.Charged)
	}
	if out.Commission != 100 {
		t.Errorf("commission = %d, want 100", out.Commission)
	}
	if out.Buyer != 1100 {
		t.Errorf("buyer = %d, want 1100", out.Buyer)
	}
	snap := h.Ledger().Snapshot()
	if snap.Revenue != 1000 {
		t.Errorf("provider revenue = %d, want 1000 (commission must not touch the seller's price)", snap.Revenue)
	}
	if snap.Commission != 100 {
		t.Errorf("ledger commission = %d, want 100", snap.Commission)
	}
	if acct := snap.ByProvider["cheap"]; acct.Commission != 100 {
		t.Errorf("per-provider commission = %d, want 100", acct.Commission)
	}
}

func TestNoCommissionByDefault(t *testing.T) {
	set := ratesTable(map[string]RateCard{
		"cheap": {PerRequestMicros: 1000},
	})
	fake := &ScriptedTEE{Reply: func(call int, spec jobs.Spec) (Result, error) {
		return cardReply(call, spec, 1000, false)
	}}
	h, _ := New(Config{TEE: fake, Rates: set, Store: NewReceiptStore(t.TempDir()), Verify: acceptAll})
	out, err := h.ExecuteForModel(context.Background(), "tenant", "m", nil, buildFor, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if out.Commission != 0 || out.Buyer != 1000 {
		t.Errorf("commission/buyer = %d/%d, want 0/1000", out.Commission, out.Buyer)
	}
}

package hub

import (
	"context"
	"errors"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// These tests exercise the buyer-facing source dimension: the market view that
// keeps provider rows distinct, and the scheduler entry point that pins a job
// to one named source.

// testMarketHub builds a Hub with two online agents serving sparsely
// overlapping model sets, so the row structure of the market is non-trivial.
func testMarketHub(t *testing.T) *Hub {
	t.Helper()
	h := scriptedHub(t, Config{
		Rates: ratesTable(map[string]RateCard{
			"cheap": {PerRequestMicros: 1000},
			"dear":  {PerRequestMicros: 900},
		}),
		AgentKeys: map[string][]byte{"cheap": []byte("c"), "dear": []byte("d")},
	})
	drop := agentsOnlineWith(h, "cheap", RateCard{PerRequestMicros: 100}, []string{"alpha", "beta"})
	_ = agentsOnlineWith(h, "dear", RateCard{PerRequestMicros: 400}, []string{"beta", "gamma"})
	t.Cleanup(drop)
	return h
}

// TestMarketQuotesKeepsSourcesSeparate pins the expanded view's core invariant:
// a model served by two providers appears as two rows, each citing its own
// source, unlike the model-aggregated directory which collapses to one.
func TestMarketQuotesKeepsSourcesSeparate(t *testing.T) {
	h := testMarketHub(t)

	all := h.MarketQuotes("", "")
	if len(all) != 4 {
		t.Fatalf("MarketQuotes(\"\") = %d rows, want 4 (2 models x 2 providers, beta twice)", len(all))
	}
	// beta is served by both sources; it must appear once per source.
	sawDear := false
	for _, q := range all {
		if q.Model == "beta" && q.Provider == "dear" {
			sawDear = true
		}
	}
	if !sawDear {
		t.Fatalf("MarketQuotes(\"\") omitted dear's beta listing: both sources must show, got %v", all)
	}

	// The aggregated directory, by contrast, lists beta exactly once — at the
	// cheapest source. It answers "what models exist", not "who serves them".
	dir := h.SearchModels("")
	betaRows := 0
	for _, q := range dir {
		if q.Model == "beta" {
			betaRows++
		}
	}
	if betaRows != 1 {
		t.Fatalf("SearchModels lists beta %d times, want 1 (model-aggregated)", betaRows)
	}
}

// TestMarketQuotesProviderFilter returns every model one named source offers,
// and nothing from any other source.
func TestMarketQuotesProviderFilter(t *testing.T) {
	h := testMarketHub(t)

	got := h.MarketQuotes("cheap", "")
	if len(got) != 2 {
		t.Fatalf("MarketQuotes(\"cheap\", \"\") = %d rows, want 2 (alpha, beta)", len(got))
	}
	for _, q := range got {
		if q.Provider != "cheap" {
			t.Fatalf("MarketQuotes(\"cheap\") leaked provider %q into the view", q.Provider)
		}
		if q.Model != "alpha" && q.Model != "beta" {
			t.Fatalf("MarketQuotes(\"cheap\") listed %q, want only cheap's models", q.Model)
		}
	}

	if got := h.MarketQuotes("nobody", ""); len(got) != 0 {
		t.Fatalf("MarketQuotes unknown provider = %d rows, want none", len(got))
	}
}

// TestMarketQuotesModelFilter returns every source offering a model, each with
// its own price.
func TestMarketQuotesModelFilter(t *testing.T) {
	h := testMarketHub(t)

	got := h.MarketQuotes("", "beta")
	if len(got) != 2 {
		t.Fatalf("MarketQuotes(\"\", \"beta\") = %d rows, want 2 (cheap and dear)", len(got))
	}
	prices := map[string]uint64{}
	for _, q := range got {
		prices[q.Provider] = q.PriceMicros
	}
	if prices["cheap"] != 100 || prices["dear"] != 400 {
		t.Fatalf("beta source prices = %v, want cheap=100 dear=400", prices)
	}

	// Provider + model narrows to exactly one cell.
	one := h.MarketQuotes("dear", "beta")
	if len(one) != 1 || one[0].Provider != "dear" {
		t.Fatalf("MarketQuotes(\"dear\", \"beta\") = %v, want just dear's beta row", one)
	}
}

// TestExecuteForProviderPinsTheSource pins that a named provider is honored
// exactly: the job is dispatched to it, and only to it.
func TestExecuteForProviderPinsTheSource(t *testing.T) {
	h := testMarketHub(t)

	ran := map[string]int{}
	h.replaceTee(&ScriptedTEE{Reply: func(call int, s jobs.Spec) (Result, error) {
		ran[s.Provider]++
		stream := chunks("ok")
		r := makeReceipt(uint64(call), stream, func(r *proof.Receipt) {
			r.Provider = s.Provider
		})
		return Result{Chunks: stream, Receipt: r}, nil
	}})

	if _, err := h.ExecuteForProvider(context.Background(), "tenant", "beta", "dear", nil, buildFor, nil); err != nil {
		t.Fatalf("ExecuteForProvider dear/beta failed: %v", err)
	}
	if got := ran["dear"]; got != 1 {
		t.Fatalf("dear ran %d times, want exactly 1 (pinned)", got)
	}
	if ran["cheap"] != 0 {
		t.Fatalf("cheap ran %d times, want 0: a pinned job must not fall back to another source", ran["cheap"])
	}
}

// TestExecuteForProviderRefusesForeignProvider pins that a model the named
// provider does not serve is refused up front, never routed elsewhere.
func TestExecuteForProviderRefusesForeignProvider(t *testing.T) {
	h := testMarketHub(t)

	// alpha is cheap-only; asking dear for it must be refused outright.
	_, err := h.ExecuteForProvider(context.Background(), "tenant", "alpha", "dear", nil, buildFor, nil)
	if !errors.Is(err, ErrNoProviderForModel) {
		t.Fatalf("err = %v, want ErrNoProviderForModel: dear does not serve alpha", err)
	}

	// An unknown provider name fails the same way.
	if _, err := h.ExecuteForProvider(context.Background(), "tenant", "beta", "nobody", nil, buildFor, nil); !errors.Is(err, ErrNoProviderForModel) {
		t.Fatalf("err = %v, want ErrNoProviderForModel for unknown provider", err)
	}
}

// replaceTee swaps the Hub's scripted TEE without rebuilding the Hub, so a test
// that wants a bespoke reply can install one after the agents are up.
func (h *Hub) replaceTee(tt TEE) { h.tee = tt }
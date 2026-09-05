package hub

import (
	"context"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

// scriptedHub builds a Hub over an in-memory TEE that never egresses: these
// tests are about which provider is chosen, not about what comes back.
func scriptedHub(t *testing.T, cfg Config) *Hub {
	t.Helper()
	cfg.TEE = &ScriptedTEE{Reply: func(int, jobs.Spec) (Result, error) { return Result{}, nil }}
	return mustHub(t, cfg)
}

// agentsOnline is a test seam: it installs an online agent for a provider with
// the price the agent declared (its listing) and returns a function that takes
// it offline again, exactly as the AgentGate does when a control stream closes.
//
// The multiplexer is left nil on purpose: a listing only needs to be installed
// and removed, and register only touches the previous tunnel's mux when it
// evicts one, which these tests never do.
func agentsOnline(h *Hub, provider string, price RateCard) func() {
	h.agents.register(&agentConn{provider: provider, price: price})
	return func() { h.agents.deregister(provider, nil) }
}

// TestListingFollowsTheAgent pins that a provider's listing is a property of a
// live agent, not of the Hub's static market table: while the agent is online
// its own card is quoted, and when it goes offline the listing disappears.
func TestListingFollowsTheAgent(t *testing.T) {
	h := scriptedHub(t, Config{
		Rates:       ratesTable(map[string]RateCard{"cheap": {PerRequestMicros: 1000}}),
		AgentSecret: []byte("gate-secret"),
	})

	// The agent lists a price below the platform default for its provider.
	offline := agentsOnline(h, "cheap", RateCard{PerRequestMicros: 250})

	if got, ok := h.card("cheap"); !ok || got.PerRequestMicros != 250 {
		t.Fatalf("card while online = %v (ok=%t), want the agent's listing 250", got, ok)
	}
	if providers := h.providersForModel("m"); len(providers) != 1 || providers[0] != "cheap" {
		t.Fatalf("candidates while online = %v, want [cheap]", providers)
	}

	// The agent drops. Its listing must go with it: the provider is no longer
	// a candidate, so no job can be routed to a tunnel nobody is holding.
	offline()

	if providers := h.providersForModel("m"); len(providers) != 0 {
		t.Fatalf("candidates after the agent dropped = %v, want none: an offline provider has no listing", providers)
	}
	if _, err := h.ExecuteForModel(context.Background(), "tenant", "m", nil, buildFor, nil); err == nil {
		t.Fatal("ExecuteForModel dispatched to a provider whose agent is offline")
	}
}

// TestOneOfflineAgentDoesNotHideAnother makes sure taking one agent down does
// not empty the whole market: the remaining online providers keep their
// listings and stay schedulable.
func TestOneOfflineAgentDoesNotHideAnother(t *testing.T) {
	h := scriptedHub(t, Config{
		Rates: ratesTable(map[string]RateCard{
			"cheap": {PerRequestMicros: 1000},
			"dear":  {PerRequestMicros: 900},
		}),
		AgentSecret: []byte("gate-secret"),
	})

	dropCheap := agentsOnline(h, "cheap", RateCard{PerRequestMicros: 100})
	_ = agentsOnline(h, "dear", RateCard{PerRequestMicros: 400})

	dropCheap()

	providers := h.providersForModel("m")
	if len(providers) != 1 || providers[0] != "dear" {
		t.Fatalf("candidates = %v, want [dear]: only the online agent keeps a listing", providers)
	}
	if got, _ := h.card("dear"); got.PerRequestMicros != 400 {
		t.Fatalf("dear card = %d, want 400", got.PerRequestMicros)
	}
}

// TestMarketTableWithoutAgents keeps the escape hatch the business tests rely
// on: a Hub that does not host agent registration at all still schedules over
// its static market table.
func TestMarketTableWithoutAgents(t *testing.T) {
	h := scriptedHub(t, Config{
		Rates: ratesTable(map[string]RateCard{
			"cheap": {PerRequestMicros: 100},
			"dear":  {PerRequestMicros: 900},
		}),
	})

	providers := h.providersForModel("m")
	if len(providers) != 2 || providers[0] != "cheap" || providers[1] != "dear" {
		t.Fatalf("candidates = %v, want [cheap dear] from the market table", providers)
	}
}

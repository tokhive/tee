package hub

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

// ErrNoProviderForModel means no provider on the market can serve the
// requested model. That is a supply problem, not a failure path worth hiding
// behind a provider-specific error.
var ErrNoProviderForModel = errors.New("no provider serves this model")

// providersForModel returns the providers the Hub can route a model to, ordered
// by their effective book price for it (ascending), with ties broken by provider
// name so the order is a pure function of supply and price.
//
// The Hub only routes new work to a provider whose agent is online right now —
// a provider nobody currently egresses for cannot carry traffic, so it is not a
// candidate. A Hub that does not host agent registration at all (no agent
// secret configured: the embedded business tests driving a scripted TEE)
// schedules over the static market table instead, where every listed provider
// is treated as supply.
//
// The distinction matters on disconnect: an agent that goes offline takes its
// listing with it, and its provider stops being a candidate at any price — not
// even the platform default. Falling back to the market table whenever no agent
// happened to be online would keep routing jobs to a tunnel nobody is holding.
//
// The effective book price is per-request plus any per-model surcharge, taken
// from the agent's own card when it declared one and the platform default
// otherwise. Volume pricing is deliberately left out of the choice — the Hub
// cannot know how large a response will be before it runs the job, so an order
// that depended on it would be non-deterministic. Per-request and model
// surcharge are both known before dispatch, which is what a decision needs.
//
// An unlisted model pays no premium under a rate card, so every candidate is
// still priced. The card's numbers, not the Hub's opinion, decide the order.
func (h *Hub) providersForModel(model string) []string {
	price := func(provider string) uint64 {
		card, ok := h.card(provider)
		if !ok {
			return ^uint64(0)
		}
		book, ok := addChecked(card.PerRequestMicros, card.Premium(model))
		if !ok {
			// Saturate rather than overflow: validating refuses such a card for
			// real, but saturating keeps this sort total and deterministic even
			// against a hand-built in-memory table.
			return ^uint64(0)
		}
		return book
	}

	var providers []string
	if len(h.agentSecret) == 0 {
		// No agent gate on this Hub: the market table is the supply.
		providers = make([]string, 0, len(h.rates))
		for provider := range h.rates {
			providers = append(providers, provider)
		}
	} else {
		// Supply is exactly the agents holding a tunnel open right now.
		providers = h.agents.onlineProviders()
	}
	sort.SliceStable(providers, func(i, j int) bool {
		pi, pj := price(providers[i]), price(providers[j])
		if pi != pj {
			return pi < pj
		}
		return providers[i] < providers[j]
	})
	return providers
}

// ExecuteForModel runs a job for a model, dispatching to the cheapest provider
// that can serve it and falling back to the next cheapest on failure.
//
// A provider counts as serving the model when the job completes billably — a
// completed 2xx receipt. A cheaper provider that errors (refused, transport
// failure, provider fault, or a non-billable receipt) hands the job to the next
// candidate. If none serves the model billably, the outcome of the last attempt
// is returned: the Hub still has to be able to show what it received, and the
// receipt store records every attempt so no credential use is ever invisible.
//
// Fallback stops the moment the first byte has been relayed. Once the user has
// seen content from provider A, switching to provider B would splice two
// providers' transcripts into one response — a stream no client could parse
// and no receipt would cover. A provider that fails mid-stream is therefore
// committed to: its (truncated) outcome is returned as final, and the caller
// reports what it got rather than silently switching horses mid-response.
//
// build produces the job spec for a given provider: the Hub decides who to ask,
// but the caller supplies how to phrase the ask (host, headers, body binding)
// once, since that framing is identical across providers.
func (h *Hub) ExecuteForModel(ctx context.Context, tenant, model string, body []byte,
	build func(provider string) (jobs.Spec, error), onChunk func([]byte) error) (Outcome, error) {

	providers := h.providersForModel(model)
	if len(providers) == 0 {
		return Outcome{}, fmt.Errorf("%w: model %q", ErrNoProviderForModel, model)
	}

	var (
		last    Outcome
		err     error
		ran     bool
		relayed bool
	)
	// Count the bytes that reached the user. The relayed flag is what tells the
	// fallback loop that the response is already committed to a provider.
	relay := onChunk
	if relay != nil {
		relay = func(chunk []byte) error {
			if len(chunk) > 0 {
				relayed = true
			}
			return onChunk(chunk)
		}
	}

	for _, provider := range providers {
		spec, berr := build(provider)
		if berr != nil {
			return Outcome{}, fmt.Errorf("build spec for %q: %w", provider, berr)
		}
		ran = true
		last, err = h.Execute(ctx, tenant, model, spec, body, relay)
		if err != nil {
			if relayed {
				// The user saw this provider's bytes before it failed. There is
				// no honest way to continue with another provider: return the
				// attempt's outcome as final.
				return last, err
			}
			continue
		}
		if Billable(last.Receipt.Receipt) {
			return last, nil
		}
		// Completed but not billable — a provider that declined or errored.
		// Try the next candidate, unless its bytes already reached the user.
		if relayed {
			return last, nil
		}
	}
	if !ran {
		return Outcome{}, fmt.Errorf("%w: model %q", ErrNoProviderForModel, model)
	}
	return last, err
}

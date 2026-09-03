package hub

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

// ErrNoProviderForModel means no installed provider can serve the requested
// model. That is a supply problem, not a failure path worth hiding behind a
// provider-specific error.
var ErrNoProviderForModel = errors.New("no provider serves this model")

// providersForModel returns the installed providers that can serve a model,
// ordered by their book price for it (ascending), with ties broken by provider
// name so the order is a pure function of the policy set.
//
// The book price is the provider's own policy card: per-request plus any
// per-model surcharge. Volume pricing is deliberately left out of the choice —
// the Hub cannot know how large a response will be before it runs the job, so an
// order that depended on it would be non-deterministic. Per-request and model
// surcharge are both known before dispatch, which is what a decision needs.
//
// Every installed provider is a candidate: an unlisted model pays no premium
// under a rate card, so the request is still priced and still serveable. The
// card's numbers, not the Hub's opinion, decide the order.
func (h *Hub) providersForModel(model string) []string {
	price := func(provider string) uint64 {
		card, ok := h.policies.Get(provider)
		if !ok {
			return ^uint64(0)
		}
		book, ok := addChecked(card.RateCard.PerRequestMicros, card.RateCard.Premium(model))
		if !ok {
			// Saturate rather than overflow: validating refuses such a card for
			// real, but saturating keeps this sort total and deterministic even
			// against a hand-built in-memory set.
			return ^uint64(0)
		}
		return book
	}

	providers := h.policies.Providers()
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
		last Outcome
		err  error
		ran  bool
	)
	for _, provider := range providers {
		spec, berr := build(provider)
		if berr != nil {
			return Outcome{}, fmt.Errorf("build spec for %q: %w", provider, berr)
		}
		ran = true
		last, err = h.Execute(ctx, tenant, spec, body, onChunk)
		if err != nil {
			continue
		}
		if Billable(last.Receipt.Receipt) {
			return last, nil
		}
		// Completed but not billable — a provider that declined or errored.
		// Try the next candidate.
	}
	if !ran {
		return Outcome{}, fmt.Errorf("%w: model %q", ErrNoProviderForModel, model)
	}
	return last, err
}

// Package hub is the business side of TokenHive: everything that needs
// semantics rather than bytes.
//
// The TEE answers one question — did this exchange really happen, with exactly
// these bytes? It does not know what a model is, what a token costs, or who
// owes whom. This package answers those.
//
// The split is what makes Hub logic cheap to develop. Everything here sits on
// the far side of a single RPC, so it can be built and tested against an
// in-memory stand-in without a TEE, a network, or a real credential — which is
// the point, because pricing and quota are the parts most likely to change.
package hub

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// Wiring errors. These are construction mistakes, not runtime conditions, and
// they fire on the first call rather than the first job.
var (
	ErrNoTEE       = errors.New("hub has no TEE to dispatch to")
	ErrNoPolicySet = errors.New("hub has no policy set")
	ErrNoStore     = errors.New("hub has no receipt store")
	ErrNoVerifier  = errors.New("hub has no receipt verifier")
)

// Execution errors.
var (
	// ErrUnknownProvider means the Hub was asked to use a provider it has no
	// policy for, and therefore no price for either.
	ErrUnknownProvider = errors.New("no policy installed for provider")
	// ErrQuotaExceeded means the tenant was refused before dispatch.
	ErrQuotaExceeded = errors.New("tenant quota exhausted")
	// ErrStreamMismatch means the receipt attests bytes other than the ones
	// the Hub forwarded. Either the Hub is lying about what it delivered or
	// the TEE is not describing the same exchange; neither is settleable.
	ErrStreamMismatch = errors.New("receipt attests different bytes than the Hub forwarded")
)

// Config assembles a Hub.
type Config struct {
	// TEE is the execution seam. Required.
	TEE TEE

	// Policies carries the provider-authored policies the Hub prices against.
	// Required: without one the Hub cannot know what a provider charges, and
	// guessing would quietly move pricing authority back to the Hub.
	Policies *policy.Set

	// Store persists the receipts a provider is entitled to audit. Required:
	// a Hub that keeps no receipts removes the provider's only means of
	// noticing an execution that was hidden from it.
	Store Store

	// Verify checks a receipt's signature and attestation. Required, and
	// injected rather than hard-wired to proof.Verify so that the trust roots
	// — which attestation platforms are acceptable — stay the caller's call.
	Verify func(proof.SignedReceipt) error

	// Ledger accumulates charges. Created if nil: it holds no durable state,
	// so defaulting it cannot silently weaken any guarantee.
	Ledger *Ledger

	// Quota bounds what one tenant may consume. Nil means unlimited, which is
	// a deliberate opt-out rather than a default: a control that exists to
	// stop a credential being drained should not be on unless asked for.
	Quota *Quota

	// Clock returns the current time. Defaults to time.Now.
	Clock func() time.Time

	// Withhold, if set, suppresses the receipt carrying a given ProviderSeq
	// from the store. It exists so a test can play a Hub that hides an
	// execution and check that gap detection still catches it. A Hub that
	// wants to be trusted leaves it nil.
	Withhold func(seq uint64) bool
}

// Hub turns a job into a settled charge and an auditable receipt.
type Hub struct {
	tee      TEE
	policies *policy.Set
	store    Store
	verify   func(proof.SignedReceipt) error
	ledger   *Ledger
	quota    *Quota
	clock    func() time.Time
	withhold func(uint64) bool
}

// New builds a Hub, refusing to construct one that would settle incorrectly.
func New(cfg Config) (*Hub, error) {
	if cfg.TEE == nil {
		return nil, ErrNoTEE
	}
	if cfg.Policies == nil {
		return nil, ErrNoPolicySet
	}
	if cfg.Store == nil {
		return nil, ErrNoStore
	}
	if cfg.Verify == nil {
		return nil, ErrNoVerifier
	}
	ledger := cfg.Ledger
	if ledger == nil {
		ledger = NewLedger()
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Hub{
		tee:      cfg.TEE,
		policies: cfg.Policies,
		store:    cfg.Store,
		verify:   cfg.Verify,
		ledger:   ledger,
		quota:    cfg.Quota,
		clock:    clock,
		withhold: cfg.Withhold,
	}, nil
}

// Ledger returns the Hub's ledger, so a caller can read what it owes.
func (h *Hub) Ledger() *Ledger { return h.ledger }

// Outcome is what one request through the Hub produced.
type Outcome struct {
	// Receipt is the verified receipt. Zero if the job never reached the TEE.
	Receipt proof.SignedReceipt
	// Chunks are the response bytes the Hub forwarded to its caller.
	Chunks [][]byte
	// Charged is what the provider earned, in the micro-units of its own rate
	// card. Zero for anything the provider did not complete.
	Charged uint64
	// Stored reports whether the receipt reached the provider's audit store.
	Stored bool
}

// Execute runs one job: check quota, dispatch, verify, price, settle, store.
//
// The ordering is load-bearing in two places. Quota is checked before
// dispatch, so a refused request never consumes a ProviderSeq — if it did,
// ordinary rate limiting would punch holes in the provider's sequence and be
// indistinguishable from the Hub hiding executions. And the receipt is
// verified before anything is charged, so a forged receipt cannot move money.
func (h *Hub) Execute(ctx context.Context, tenant string, spec jobs.Spec, body []byte, onChunk func([]byte) error) (Outcome, error) {
	if h.quota != nil && !h.quota.Allow(tenant, h.clock()) {
		return Outcome{}, fmt.Errorf("%w: tenant %q", ErrQuotaExceeded, tenant)
	}

	card, ok := h.policies.Get(spec.Provider)
	if !ok {
		return Outcome{}, fmt.Errorf("%w: %q", ErrUnknownProvider, spec.Provider)
	}

	h.ledger.NoteDispatch(spec.Provider)

	res, err := h.tee.Execute(ctx, spec, body, onChunk)
	if err != nil {
		return Outcome{Chunks: res.Chunks}, err
	}

	if err := h.verify(res.Receipt); err != nil {
		return Outcome{Chunks: res.Chunks}, fmt.Errorf("verify receipt: %w", err)
	}
	h.ledger.NoteVerified(spec.Provider)

	if !res.Receipt.Receipt.MatchesStream(res.Chunks) {
		return Outcome{Chunks: res.Chunks}, ErrStreamMismatch
	}

	charged, err := Price(card.RateCard, spec.DeclaredModel, res.Receipt.Receipt)
	if err != nil {
		return Outcome{Chunks: res.Chunks}, err
	}
	h.ledger.NoteSettled(spec.Provider, charged)

	seq := res.Receipt.Receipt.ProviderSeq
	if h.withhold != nil && h.withhold(seq) {
		return Outcome{Receipt: res.Receipt, Chunks: res.Chunks, Charged: charged}, nil
	}
	if err := h.store.Put(spec.Provider, res.Receipt); err != nil {
		return Outcome{Receipt: res.Receipt, Chunks: res.Chunks, Charged: charged},
			fmt.Errorf("store receipt: %w", err)
	}
	return Outcome{Receipt: res.Receipt, Chunks: res.Chunks, Charged: charged, Stored: true}, nil
}

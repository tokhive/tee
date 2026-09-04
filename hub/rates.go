package hub

import (
	"errors"
	"fmt"
)

// This file is where the Hub's market price list lives. Pricing is a commercial
// concern kept entirely on the Hub side (seller-reported, keyed by provider) —
// it is deliberately not part of the whitelist policy, which is loaded into the
// TEE as deployment config and says nothing about money.

// Rate-card bounds. Prices are carried as integer micro-units rather than
// floats: they feed integer arithmetic that must never overflow, and a float
// in this position lets the same price encode differently on different
// platforms. One micro is 1e-6 of the provider's currency unit, so the bound
// is ~1.1e6 units.
const (
	MaxRateModels      = 64
	MaxModelNameLength = 64

	// MaxRateMicros bounds a single price component so the Hub's pricing
	// arithmetic cannot overflow on a seller-chosen rate card.
	MaxRateMicros = uint64(1) << 40
)

// ErrInvalidRateCard means a rate card failed structural validation. A card
// this malformed must not be accepted, because pricing arithmetic over it is
// the one place an overflow would silently undercharge the seller.
var ErrInvalidRateCard = errors.New("invalid rate card")

// RateCard is a seller's price list, in integer micro-units (1e-6 of the
// provider's currency unit). It is Hub-side commercial data reported by the
// seller through the Hub's own onboarding, and the Hub applies it. The receipt
// still attests the two quantities the card prices on: the completion state
// (key 12) and the response size (key 11) come off the TEE receipt, and the
// model name is the one the Hub declared for the job. So a charge remains
// reproducible by anyone holding the receipt and the card the Hub used.
type RateCard struct {
	// PerRequestMicros is charged once for a request the provider completed.
	PerRequestMicros uint64 `json:"per_request_micros,omitempty"`
	// PerMegabyteMicros is charged per whole mebibyte of attested response
	// bytes, rounded up, so the smallest non-empty response bills one unit.
	PerMegabyteMicros uint64 `json:"per_megabyte_micros,omitempty"`
	// ModelPremiumMicros adds a surcharge keyed by the model the Hub declared
	// in the job spec. An undeclared or unlisted model pays no premium.
	ModelPremiumMicros map[string]uint64 `json:"model_premium_micros,omitempty"`
}

// Validate checks that the card is structurally sound and that every price
// component is small enough for the Hub's arithmetic to stay in range.
//
// A zero card is valid and means the provider works for free — that is the
// seller's call to make, not the validator's.
func (r RateCard) Validate() error {
	if r.PerRequestMicros > MaxRateMicros {
		return fmt.Errorf("%w: PerRequestMicros %d exceeds %d",
			ErrInvalidRateCard, r.PerRequestMicros, MaxRateMicros)
	}
	if r.PerMegabyteMicros > MaxRateMicros {
		return fmt.Errorf("%w: PerMegabyteMicros %d exceeds %d",
			ErrInvalidRateCard, r.PerMegabyteMicros, MaxRateMicros)
	}
	if len(r.ModelPremiumMicros) > MaxRateModels {
		return fmt.Errorf("%w: %d model prices exceeds %d",
			ErrInvalidRateCard, len(r.ModelPremiumMicros), MaxRateModels)
	}
	for model, micros := range r.ModelPremiumMicros {
		if model == "" || len(model) > MaxModelNameLength {
			return fmt.Errorf("%w: model name %q length outside [1,%d]",
				ErrInvalidRateCard, model, MaxModelNameLength)
		}
		if micros > MaxRateMicros {
			return fmt.Errorf("%w: premium for %q is %d, exceeds %d",
				ErrInvalidRateCard, model, micros, MaxRateMicros)
		}
	}
	return nil
}

// Premium returns the surcharge for a declared model, or zero if the card
// prices nothing for it.
func (r RateCard) Premium(model string) uint64 {
	return r.ModelPremiumMicros[model]
}

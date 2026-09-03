package hub

import (
	"fmt"
)

// CommissionRate is the fixed fraction the Hub keeps over what the provider
// charges the buyer.
//
// Pricing authority stays with the provider on the seller side (the receipt
// settles exactly what the provider's own rate card says); this value is purely
// the Hub's commerce toward the buyer, so it lives in the Hub's configuration
// rather than in any signed structure.
type CommissionRate struct {
	// BasisPoints expresses the Hub's cut in hundredths of a percent: 100 is
	// one percent, 1000 is ten percent. Zero means the Hub takes nothing.
	BasisPoints uint64
}

// CommissionOn returns the Hub's cut for a charge settled at seller micros,
// rounded down to a whole micro-unit so a signed seller price plus a whole
// commission always reconciles back to the provider's number.
//
// The rounding is intentionally toward the buyer: the Hub's cut is an
// add-on the Hub decided, and undercharging a buyer by part of a micro is the
// safe direction for a commerce decision the provider never agreed to.
func (r CommissionRate) CommissionOn(seller uint64) (uint64, error) {
	if r.BasisPoints == 0 || seller == 0 {
		return 0, nil
	}
	scaled, ok := mulChecked(seller, r.BasisPoints)
	if !ok {
		return 0, fmt.Errorf("%w: commission %d basis points on %d",
			ErrPriceOverflow, r.BasisPoints, seller)
	}
	return scaled / 10000, nil
}

// BuyerPrice returns what the buyer is billed for a charge settled at seller
// micros: the seller price plus the commission.
func (r CommissionRate) BuyerPrice(seller uint64) (uint64, error) {
	commission, err := r.CommissionOn(seller)
	if err != nil {
		return 0, err
	}
	buyer, ok := addChecked(seller, commission)
	if !ok {
		return 0, fmt.Errorf("%w: seller %d plus commission %d", ErrPriceOverflow, seller, commission)
	}
	return buyer, nil
}

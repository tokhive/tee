package hub

import (
	"errors"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// mebibyte is the unit response volume is billed in.
const mebibyte = uint64(1) << 20

// ErrPriceOverflow means a rate card prices a receipt beyond what a uint64
// charge can hold. It is a property of the card and the size, not of a
// particular caller, so it fires the same way for every job run against that
// card: treat it as a misconfiguration, not a transient failure.
var ErrPriceOverflow = errors.New("rate card prices this receipt out of range")

// sessionStatus is the sentinel StatusCode a streaming-session receipt carries.
// The Hub dedicates 101 — the HTTP "Switching Protocols" upgrade that a session
// begins with — to sessions, so a receipt's status alone distinguishes a
// session from an ordinary request. Billable honors it for that exact reason.
const sessionStatus = 101

// Billable reports whether a receipt earned the provider anything.
//
// Only a completed success counts. For requests that is a 2xx; for streaming
// sessions the provider's handshake receipt carries StatusCode 101, which is
// the success marker for that shape. A 401, a 429, or a stream cut off mid-body
// are all attested exactly like a success — because those receipts are what let
// the Hub prove it did not receive what it was asked to pay for — but they are
// not worth money.
func Billable(r proof.Receipt) bool {
	if r.Completion != proof.CompletionComplete {
		return false
	}
	if r.StatusCode >= 200 && r.StatusCode < 300 {
		return true
	}
	return r.StatusCode == sessionStatus
}

// Price computes what a receipt earns under a seller's rate card, in the
// integer micro-units the card is written in.
//
// Every input is attested: completion state and response size come off the
// receipt, and the model is the one the Hub declared into the job spec, which
// the job spec hash binds. That makes a charge reproducible by anyone holding
// the receipt and the card the Hub applied — a Hub that pays a provider less
// than its published card specifies produces a number that does not reconcile.
//
// A receipt that is not billable prices at zero rather than erroring: refusal
// to pay is a normal outcome, not a failure.
func Price(card RateCard, declaredModel string, r proof.Receipt) (uint64, error) {
	if !Billable(r) {
		return 0, nil
	}
	total, ok := addChecked(card.PerRequestMicros, card.Premium(declaredModel))
	if !ok {
		return 0, ErrPriceOverflow
	}
	// Rounded up, so the smallest non-empty response still bills one unit.
	volumes := (r.ResponseBytes + mebibyte - 1) / mebibyte
	volume, ok := mulChecked(volumes, card.PerMegabyteMicros)
	if !ok {
		return 0, ErrPriceOverflow
	}
	total, ok = addChecked(total, volume)
	if !ok {
		return 0, ErrPriceOverflow
	}
	return total, nil
}

func addChecked(a, b uint64) (uint64, bool) {
	sum := a + b
	return sum, sum >= a
}

func mulChecked(a, b uint64) (uint64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	product := a * b
	return product, product/b == a
}

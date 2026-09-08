package hub

import (
	"errors"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// mebibyte is the unit exchange volume is billed in.
const mebibyte = uint64(1) << 20

// ErrPriceOverflow means a rate card prices a receipt beyond what a uint64
// charge can hold. It is a property of the card and the size, not of a
// particular caller, so it fires the same way for every job run against that
// card: treat it as a misconfiguration, not a transient failure.
var ErrPriceOverflow = errors.New("rate card prices this receipt out of range")

// sessionStatus is the sentinel StatusCode a streaming-session receipt carries.
// The Hub dedicates 101 — the HTTP "Switching Protocols" upgrade that a session
// begins with — to sessions, so a receipt's status alone distinguishes a
// session from an ordinary request. Price honors it for that exact reason.
const sessionStatus = 101

// Billable reports whether a receipt earns the provider the flat per-request
// fee and model premium.
//
// Only a completed success does. For requests that is a 2xx; for streaming
// sessions the provider's handshake receipt carries StatusCode 101, which is
// the success marker for that shape. A 401, a 429, or a stream cut off mid-body
// are all attested exactly like a success — because those receipts are what let
// the Hub prove it did not receive what it was asked to pay for — but they do
// not earn the flat fee. A truncated stream still earns the volume rate for the
// bytes it did deliver (see Price); it just is not a completed success.
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
// Every quantity is attested: completion state, request size, and response
// size come off the receipt, and the model is the one the Hub declared into
// the job spec, which the job spec hash binds. The response volume is bounded
// by relayedBytes — the length of the stream the Hub actually relayed, which
// the receipt's StreamHash binds to exactly those bytes — so a charge stays
// reproducible by anyone holding the receipt, the card, and the relayed
// stream: a Hub that pays a provider less than its published card specifies
// produces a number that does not reconcile.
//
// relayedBytes is the actual delivered response length, not the job's cap.
// The TEE rejects whole chunks that cross MaxResponseBytes (the overflow is
// attested in ResponseBytes but relayed to nobody), so the delivered prefix
// can end far below the cap — or at zero, when the first chunk is already too
// large — and ResponseBytes can exceed it. Billing against either number
// would charge the buyer for bytes never received; the relayed length is the
// only one that is what the buyer got. For a streaming session, whose
// ResponseBytes is exactly what was relayed, pass the relayed count as-is.
//
// What earns what:
//   - A completed success (2xx, or session 101) earns the flat per-request fee,
//     the model premium, and the volume rate over the attested request plus
//     delivered response bytes.
//   - A truncated stream earns only the volume rate, over the request plus the
//     delivered response bytes. The seller paid the upstream for those tokens,
//     so the buyer pays for them; the flat fee and premium are margin, and
//     margin is earned only on completed work.
//   - Anything else — a declined request (4xx/5xx), a failed exchange, or a
//     truncation that never delivered a byte — prices at zero: nothing arrived
//     worth paying for.
//
// A receipt that earns nothing prices at zero rather than erroring: refusal to
// pay is a normal outcome, not a failure.
func Price(card RateCard, declaredModel string, relayedBytes uint64, r proof.Receipt) (uint64, error) {
	if r.Completion != proof.CompletionComplete && r.Completion != proof.CompletionTruncated {
		return 0, nil
	}
	if (r.StatusCode < 200 || r.StatusCode >= 300) && r.StatusCode != sessionStatus {
		return 0, nil
	}

	// The receipt attests everything the provider sent; the Hub relayed a
	// prefix of it. The buyer pays for the intersection: never more than the
	// receipt claims, never more than was actually delivered.
	delivered := r.ResponseBytes
	if relayedBytes < delivered {
		delivered = relayedBytes
	}
	if r.Completion == proof.CompletionTruncated && delivered == 0 {
		return 0, nil
	}

	// The seller's upstream bill grows with both the prompt and the response,
	// and both sizes are attested, so volume covers input plus delivered
	// output. Rounded up, so the smallest non-empty exchange bills one unit.
	billed, ok := addChecked(r.RequestBytes, delivered)
	if !ok {
		return 0, ErrPriceOverflow
	}
	volumes := (billed + mebibyte - 1) / mebibyte
	total, ok := mulChecked(volumes, card.PerMegabyteMicros)
	if !ok {
		return 0, ErrPriceOverflow
	}

	if r.Completion == proof.CompletionComplete {
		fee, ok := addChecked(card.PerRequestMicros, card.Premium(declaredModel))
		if !ok {
			return 0, ErrPriceOverflow
		}
		total, ok = addChecked(total, fee)
		if !ok {
			return 0, ErrPriceOverflow
		}
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

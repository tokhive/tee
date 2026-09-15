package evidence

import (
	"context"
	"errors"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// Fetcher resolves an evidence hash to full evidence bytes. It is the abstract
// half of evidence retrieval; incarnations read from a local store or a remote
// /v1/evidence endpoint.
type Fetcher interface {
	Fetch(ctx context.Context, id platform.Identity) ([]byte, error)
}

// Chain tries fetchers in order until one resolves the evidence. It composes
// the in-memory "what this process has seen" cache with the durable local store
// and, when configured, a remote peer's endpoint, so a hash-only receipt
// resolves from whichever source actually holds the bytes.
type Chain struct {
	fetchers []Fetcher
}

// NewChain returns a Chain over the given fetchers, tried in order.
func NewChain(fetchers ...Fetcher) *Chain {
	return &Chain{fetchers: fetchers}
}

// Add appends one more fetcher to try after the existing ones.
func (c *Chain) Add(f Fetcher) { c.fetchers = append(c.fetchers, f) }

// Fetch returns the first fetcher's successful result. If every fetcher misses,
// it returns ErrNoEvidence; a non-miss error from the last fetcher is surfaced
// because it explains why retrieval failed.
func (c *Chain) Fetch(ctx context.Context, id platform.Identity) ([]byte, error) {
	var lastErr error
	for _, f := range c.fetchers {
		if f == nil {
			continue
		}
		b, err := f.Fetch(ctx, id)
		if err == nil {
			return b, nil
		}
		if !errors.Is(err, ErrNoEvidence) {
			lastErr = err
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrNoEvidence
}

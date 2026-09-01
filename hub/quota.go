package hub

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrInvalidQuota means a quota was constructed with parameters that would
// make it either meaningless or permanently open.
var ErrInvalidQuota = errors.New("invalid quota")

// Quota bounds how much one tenant may consume in a window.
//
// Quota belongs to the Hub rather than the TEE because it needs state
// accumulated across jobs, and the TEE is deliberately stateless apart from
// the provider sequence. It is enforced before dispatch, so a refused request
// costs the provider nothing at all.
//
// This is a fixed window: simple, bounded memory, and adequate for protecting
// a shared credential from being drained. A sliding window would be fairer at
// the boundary and is a change to this file when it matters.
type Quota struct {
	limit  int64
	window time.Duration

	mu      sync.Mutex
	windows map[string]*quotaWindow
}

type quotaWindow struct {
	start time.Time
	used  int64
}

// NewQuota returns a quota allowing limit requests per tenant per window.
//
// Both parameters are required. A zero limit that silently meant "unlimited"
// would be indistinguishable from a misconfiguration — the wrong way round for
// a control whose job is to stop a credential being drained. Callers that want
// no quota pass nil instead.
func NewQuota(limit int64, window time.Duration) (*Quota, error) {
	if limit < 1 {
		return nil, fmt.Errorf("%w: limit %d must be at least 1", ErrInvalidQuota, limit)
	}
	if window <= 0 {
		return nil, fmt.Errorf("%w: window %v must be positive", ErrInvalidQuota, window)
	}
	return &Quota{limit: limit, window: window, windows: make(map[string]*quotaWindow)}, nil
}

// Allow reports whether a tenant may consume one more request, consuming it if
// so. Not thread-safe in intent across two calls for the same tenant unless
// both go through here.
func (q *Quota) Allow(tenant string, now time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	w := q.windows[tenant]
	if w == nil || now.Sub(w.start) >= q.window {
		q.windows[tenant] = &quotaWindow{start: now, used: 1}
		return true
	}
	if w.used >= q.limit {
		return false
	}
	w.used++
	return true
}

// Remaining reports how many requests a tenant has left in the current window.
func (q *Quota) Remaining(tenant string, now time.Time) int64 {
	q.mu.Lock()
	defer q.mu.Unlock()

	w := q.windows[tenant]
	if w == nil || now.Sub(w.start) >= q.window {
		return q.limit
	}
	if left := q.limit - w.used; left > 0 {
		return left
	}
	return 0
}

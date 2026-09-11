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

// MaxQuotaTenants is how many tenants one Quota tracks at once. It exists
// because the tenant name is attacker-influenced whenever the Hub runs without
// a key map: an unbounded windows table would let any caller grow Hub memory
// by inventing names, one entry per name, forever. The cap is generous enough
// that a provisioned Hub (whose tenant set is fixed by its key map) never
// reaches it.
const MaxQuotaTenants = 1 << 16

// Quota bounds how much one tenant may consume in a window.
//
// Quota belongs to the Hub rather than the TEE because it needs state
// accumulated across jobs, and the TEE is deliberately stateless apart from
// the provider sequence. It is enforced before dispatch, so a refused request
// costs the provider nothing at all.
//
// This is a fixed window: simple, bounded memory, and adequate for protecting
// a shared credential from being drained. A sliding window would be fairer at
// the boundary and is a change to this file when it matters. The table is
// swept of expired windows on demand and capped at MaxQuotaTenants; see
// admit for what happens when it is full.
type Quota struct {
	limit      int64
	window     time.Duration
	maxTenants int

	mu        sync.Mutex
	windows   map[string]*quotaWindow
	nextSweep time.Time
}

type quotaWindow struct {
	start time.Time
	used  int64
}

// NewQuota returns a quota allowing limit requests per tenant per window,
// tracking up to MaxQuotaTenants tenants at a time.
//
// Both parameters are required. A zero limit that silently meant "unlimited"
// would be indistinguishable from a misconfiguration — the wrong way round for
// a control whose job is to stop a credential being drained. Callers that want
// no quota pass nil instead.
func NewQuota(limit int64, window time.Duration) (*Quota, error) {
	return NewQuotaBounded(limit, window, MaxQuotaTenants)
}

// NewQuotaBounded is NewQuota with an explicit tenant cap, so a caller can
// size the table to its provisioned tenant set (or a test can exercise the
// full-table path without allocating MaxQuotaTenants entries).
func NewQuotaBounded(limit int64, window time.Duration, maxTenants int) (*Quota, error) {
	if limit < 1 {
		return nil, fmt.Errorf("%w: limit %d must be at least 1", ErrInvalidQuota, limit)
	}
	if window <= 0 {
		return nil, fmt.Errorf("%w: window %v must be positive", ErrInvalidQuota, window)
	}
	if maxTenants < 1 {
		return nil, fmt.Errorf("%w: tenant cap %d must be at least 1", ErrInvalidQuota, maxTenants)
	}
	return &Quota{
		limit:      limit,
		window:     window,
		maxTenants: maxTenants,
		windows:    make(map[string]*quotaWindow),
	}, nil
}

// Allow reports whether a tenant may consume one more request, consuming it if
// so. Not thread-safe in intent across two calls for the same tenant unless
// both go through here.
//
// A tenant the table has no room to track is refused rather than admitted
// untracked: an untracked tenant has no quota, so admitting one would hand out
// exactly the unbounded consumption this control exists to prevent. See admit.
func (q *Quota) Allow(tenant string, now time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	w := q.windows[tenant]
	if w != nil && now.Sub(w.start) < q.window {
		if w.used >= q.limit {
			return false
		}
		w.used++
		return true
	}
	// Either the tenant is new, or its tracked window has run out and this
	// request starts a fresh one. Only a genuinely new entry needs room.
	if w == nil && !q.admit(now) {
		return false
	}
	q.windows[tenant] = &quotaWindow{start: now, used: 1}
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

// admit makes room for one new tenant and reports whether there is any.
//
// Expired windows are swept first, so a table that is merely full of tenants
// from a past window always accepts the newcomer. If every tracked window is
// still live the table is genuinely at capacity, and the newcomer is refused.
//
// Refusing is deliberate. The alternative — evicting a live entry — would hand
// the evicted tenant a fresh allowance, which is a quota bypass reachable by
// anyone who can add names; a Hub that would rather serve new tenants than
// hold them to a quota should raise its cap or provision tenant keys, not
// silently drop accounting. The sweep is amortised: it runs at most once per
// window, so a full table cannot turn every admission into a linear scan.
func (q *Quota) admit(now time.Time) bool {
	if len(q.windows) < q.maxTenants {
		return true
	}
	q.sweep(now)
	return len(q.windows) < q.maxTenants
}

// sweep drops windows that have expired as of now, at most once per window.
func (q *Quota) sweep(now time.Time) {
	if now.Before(q.nextSweep) {
		return
	}
	q.nextSweep = now.Add(q.window)
	for tenant, w := range q.windows {
		if now.Sub(w.start) >= q.window {
			delete(q.windows, tenant)
		}
	}
}

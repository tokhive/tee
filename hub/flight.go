package hub

import (
	"errors"
	"fmt"
	"sync"
)

// ErrTooManyInflight means the tenant already has as many jobs running as the
// Hub will run for it at the same time.
var ErrTooManyInflight = errors.New("tenant has too many jobs in flight")

// MaxFlightTenants bounds how many tenants one limiter tracks at once. Like
// MaxQuotaTenants it exists because the tenant name is attacker-influenced in
// open mode, but it binds far more loosely: an entry is dropped the moment its
// count returns to zero, so the table holds only tenants that have something
// running right now, and its size is already bounded by the number of jobs in
// flight. The cap therefore only ever bites on a Hub genuinely serving that
// many tenants at once.
const MaxFlightTenants = 1 << 16

// flightLimiter bounds how many jobs one tenant may have in flight at once.
//
// It is the fairness control for a shared provider, and it has to live in the
// Hub because nothing below it knows who anyone is. The TEE pools provider
// connections per (provider, host) and holds a slot for every connection it
// keeps — idle or busy — until its idle window expires; tenants are a Hub
// concept the TEE never sees (a job's tenant is not in the JobSpec, so it is
// not attested either). Under that layout a single tenant can take every slot a
// shared provider has and leave everyone else queued behind it for as long as
// its requests keep arriving. Bounding each tenant's share at the only layer
// that can tell tenants apart is what makes the pool's capacity shared rather
// than first-come-wins.
//
// The bound is on concurrency, not on rate: a tenant may run as many jobs as it
// likes over time, just not more than its share at one instant. A streaming
// session counts for as long as it is open, which is deliberate — a session
// holds a provider connection for the whole time it lasts, so it is exactly the
// shape of job that can starve the others, and it is why closing the session
// (not returning from the call that opened it) is what returns the slot.
//
// Sharing one count between requests and sessions is also deliberate: they draw
// on the same pool, so a tenant running its full share of sessions and its full
// share of requests would occupy twice the share the control promises.
type flightLimiter struct {
	maxPerTenant int
	maxTenants   int

	mu  sync.Mutex
	per map[string]int
}

// newFlightLimiter returns a limiter allowing maxPerTenant concurrent jobs per
// tenant and tracking at most maxTenants tenants at once. maxPerTenant must be
// at least 1: a zero there would refuse everything, which is spelled by not
// configuring a limiter at all.
func newFlightLimiter(maxPerTenant, maxTenants int) *flightLimiter {
	if maxTenants < 1 {
		maxTenants = MaxFlightTenants
	}
	return &flightLimiter{
		maxPerTenant: maxPerTenant,
		maxTenants:   maxTenants,
		per:          make(map[string]int),
	}
}

// acquire reserves one in-flight slot for the tenant and reports whether it got
// one. A nil limiter admits everything, which is how "no bound configured" is
// spelled — the same opt-out shape as a nil Quota — so callers never need to
// check for one.
func (f *flightLimiter) acquire(tenant string) bool {
	if f == nil {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	n := f.per[tenant]
	if n >= f.maxPerTenant {
		return false
	}
	// A tenant with nothing running is a new entry, so the table bound applies
	// here and nowhere else. A full table is refused rather than evicted: an
	// eviction would erase some other tenant's count and hand it a fresh
	// allowance, which is a way to exceed the bound by outrunning the sweep —
	// the same reasoning the quota table's full-table path follows. Entries
	// leave at zero (see release), so a table that is merely stale cannot fill.
	if n == 0 && f.maxTenants > 0 && len(f.per) >= f.maxTenants {
		return false
	}
	f.per[tenant] = n + 1
	return true
}

// release returns one in-flight slot. The entry is dropped at zero so a table
// of tenants that have finished everything cannot accumulate.
func (f *flightLimiter) release(tenant string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	switch n := f.per[tenant]; {
	case n <= 1:
		delete(f.per, tenant)
	default:
		f.per[tenant] = n - 1
	}
}

// active reports how many jobs the tenant has in flight. It exists for tests
// and operators; enforcement never reads it.
func (f *flightLimiter) active(tenant string) int {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.per[tenant]
}

// beginJob admits one job against every tenant-scoped control and returns the
// pairing release. Every caller that starts a job must hold the returned
// release for as long as the job runs; forgetting it leaks the tenant's
// allowance, so the shape is deliberately "one call, one defer".
//
// Order matters: the in-flight slot is taken before the quota and budget are
// consulted, and given back if either refuses. A request that is turned away on
// rate or spend is not running, so it must not leave the tenant holding
// concurrency it cannot use — one refused call could otherwise hold a slot for
// as long as its caller's context lives.
func (h *Hub) beginJob(tenant string) (func(), error) {
	if !h.flight.acquire(tenant) {
		return nil, fmt.Errorf("%w: tenant %q", ErrTooManyInflight, tenant)
	}
	if err := h.admitTenant(tenant); err != nil {
		h.flight.release(tenant)
		return nil, err
	}
	return func() { h.flight.release(tenant) }, nil
}

// flightConn ties a session's in-flight slot to the session's lifetime.
//
// A session is admitted like any other job, but it does not finish when the
// call that opened it returns — it runs until the connection closes. Releasing
// the slot there (a plain defer) would let a caller run unbounded sessions by
// opening them in a loop, each one holding a provider connection the bound
// believed was free. Handing the slot to the connection instead makes the two
// lifetimes the same thing, and Close idempotent so the relay and the timeout
// watchdog can both close it.
type flightConn struct {
	SessionConn
	release func()
	once    sync.Once
}

// newFlightConn returns conn that returns its tenant's slot when closed.
func newFlightConn(conn SessionConn, release func()) SessionConn {
	return &flightConn{SessionConn: conn, release: release}
}

// Close ends the session and gives back its in-flight slot. The release runs
// exactly once however many times Close is called.
func (c *flightConn) Close() error {
	err := c.SessionConn.Close()
	c.once.Do(c.release)
	return err
}

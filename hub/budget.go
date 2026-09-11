package hub

import (
	"errors"
	"fmt"
	"sync"
)

// ErrInvalidBudget means a budget table was constructed with an entry that
// would either be meaningless or refuse everything.
var ErrInvalidBudget = errors.New("invalid budget")

// Budget caps how much each tenant may be billed in total.
//
// It is the cumulative counterpart of MaxJobMicros. The ceiling bounds one job;
// the budget bounds the sum of them, which is what actually protects a buyer
// from a hostile seller's rate card draining an account over many jobs. The
// per-job ceiling cannot do that: a card that prices just under the ceiling
// bills forever, and nothing in the Hub was counting.
//
// Accounting is per provisioned tenant rather than derived from the request, so
// the table cannot be grown by a caller. A tenant that no operator has given a
// ceiling has none — the same deliberate opt-out as Quota and MaxJobMicros, and
// the only safe shape: a generic ceiling for arbitrary names would need one map
// entry per invented name, which is the unbounded-growth problem the quota
// table just stopped having.
//
// Enforcement is check-then-record, because the charge is only known once the
// receipt is priced: the Hub admits a job when the tenant is under its ceiling
// and records the bill after it settles. Concurrent jobs can therefore overshoot
// by at most (in-flight jobs x MaxJobMicros) — bounded, and the reason a Hub
// that must never overshoot sets MaxJobMicros as well.
type Budget struct {
	budgets map[string]uint64

	mu   sync.Mutex
	used map[string]uint64
}

// NewBudget returns a budget tracking the given per-tenant ceilings, in the
// same integer micro-units as a rate card. An empty table is rejected: a
// constructor that accepted one could only ever have been meant as "no
// budgets", which is spelled by passing no Budget at all.
func NewBudget(budgets map[string]uint64) (*Budget, error) {
	if len(budgets) == 0 {
		return nil, fmt.Errorf("%w: no tenant budgets", ErrInvalidBudget)
	}
	copied := make(map[string]uint64, len(budgets))
	for tenant, micros := range budgets {
		if tenant == "" {
			return nil, fmt.Errorf("%w: empty tenant name", ErrInvalidBudget)
		}
		if micros == 0 {
			return nil, fmt.Errorf("%w: tenant %q has a zero ceiling, which would refuse every job it sends", ErrInvalidBudget, tenant)
		}
		copied[tenant] = micros
	}
	return &Budget{budgets: copied, used: make(map[string]uint64, len(budgets))}, nil
}

// Allow reports whether a tenant may start another job: true while it is still
// under its ceiling. A tenant with no provisioned budget is always admitted and
// is never tracked, so the used table is bounded by the budget table.
func (b *Budget) Allow(tenant string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	ceiling, ok := b.budgets[tenant]
	if !ok {
		return true
	}
	return b.used[tenant] < ceiling
}

// Record adds a settled charge to a tenant's total. It is called only where
// money actually moved — a job the Hub refused to price, or one whose receipt
// could not be stored, settles nothing and must not consume budget.
func (b *Budget) Record(tenant string, micros uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.budgets[tenant]; !ok {
		return
	}
	used := b.used[tenant]
	if sum := used + micros; sum >= used {
		used = sum
	} else {
		// Saturate rather than wrap: a total that wrapped to a small number
		// would hand the tenant its whole budget back.
		used = ^uint64(0)
	}
	b.used[tenant] = used
}

// Remaining reports how much budget a tenant has left, and whether it has a
// budget at all. An exhausted tenant reports zero, not a negative.
func (b *Budget) Remaining(tenant string) (uint64, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ceiling, ok := b.budgets[tenant]
	if !ok {
		return 0, false
	}
	if used := b.used[tenant]; used < ceiling {
		return ceiling - used, true
	}
	return 0, true
}

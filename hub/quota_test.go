package hub

import (
	"errors"
	"testing"
	"time"
)

// The quota table is the one piece of Hub state an unauthenticated caller can
// make grow: with no key map configured, the tenant name is whatever the caller
// sends, so every invented name would otherwise be one more permanent map
// entry. These tests pin the bound and the policy that keeps it honest.

func TestQuotaSweepsExpiredWindowsBeforeRefusingANewTenant(t *testing.T) {
	q, err := NewQuotaBounded(1, time.Minute, 2)
	if err != nil {
		t.Fatalf("NewQuotaBounded: %v", err)
	}
	now := time.Now()

	if !q.Allow("a", now) || !q.Allow("b", now) {
		t.Fatalf("the first two tenants must fit an empty table")
	}
	// Full of live windows: the newcomer is refused rather than evicting one.
	if q.Allow("c", now) {
		t.Fatalf("a full table of live windows must refuse a new tenant")
	}
	// Once the tracked windows expire, the same newcomer is admitted: a full
	// table must never become a permanent one.
	if !q.Allow("c", now.Add(2*time.Minute)) {
		t.Fatalf("an expired window must make room for a new tenant")
	}
}

func TestQuotaNeverEvictsALiveTenantToAdmitANewOne(t *testing.T) {
	// One slot, two requests per window. If admitting "b" evicted "a", a's
	// counter would restart and it would get three requests out of a
	// two-request quota — a bypass reachable by anyone who can add names.
	q, err := NewQuotaBounded(2, time.Minute, 1)
	if err != nil {
		t.Fatalf("NewQuotaBounded: %v", err)
	}
	now := time.Now()

	if !q.Allow("a", now) {
		t.Fatalf("first request for a must pass")
	}
	if q.Allow("b", now) {
		t.Fatalf("a full table must refuse b")
	}
	if !q.Allow("a", now) {
		t.Fatalf("a's second request must pass")
	}
	if q.Allow("a", now) {
		t.Fatalf("a's third request must be refused: its window was reset by an eviction")
	}
}

func TestQuotaRefusesAtTheBoundNotBeyondIt(t *testing.T) {
	q, err := NewQuotaBounded(1, time.Hour, 4)
	if err != nil {
		t.Fatalf("NewQuotaBounded: %v", err)
	}
	now := time.Now()

	for i := 0; i < 4; i++ {
		tenant := string(rune('a' + i))
		if !q.Allow(tenant, now) {
			t.Fatalf("tenant %q must fit the table", tenant)
		}
	}
	if q.Allow("e", now) {
		t.Fatalf("the table is at its bound; a fifth tenant must be refused")
	}
	// The bound must not have leaked into the per-window allowance of tenants
	// already tracked: a's window is still spent, and its refusal must be the
	// quota, not the table.
	if q.Remaining("a", now) != 0 {
		t.Fatalf("remaining for a = %d, want 0", q.Remaining("a", now))
	}
	if q.Remaining("e", now) != 1 {
		t.Fatalf("remaining for an untracked tenant = %d, want the full limit", q.Remaining("e", now))
	}
}

func TestQuotaBoundedRejectsANonPositiveCap(t *testing.T) {
	if _, err := NewQuotaBounded(1, time.Minute, 0); !errors.Is(err, ErrInvalidQuota) {
		t.Errorf("cap 0 error = %v, want ErrInvalidQuota", err)
	}
}

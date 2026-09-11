package hub

import "testing"

func TestLedgerSaturatesOnOverflow(t *testing.T) {
	l := NewLedger()

	// A total at the ceiling plus one more must saturate, never wrap into a
	// small number: a wrapped lifetime revenue would understate what a provider
	// is owed in the direction that matters.
	l.NoteSettled("p", ^uint64(0))
	l.NoteSettled("p", 1)
	snap := l.Snapshot()
	if snap.Revenue != ^uint64(0) {
		t.Fatalf("revenue = %d, want saturated %d", snap.Revenue, ^uint64(0))
	}
	if acct := snap.ByProvider["p"]; acct.Revenue != ^uint64(0) {
		t.Fatalf("provider revenue = %d, want saturated %d", acct.Revenue, ^uint64(0))
	}

	l.NoteCommission("p", ^uint64(0))
	l.NoteCommission("p", 1)
	snap = l.Snapshot()
	if snap.Commission != ^uint64(0) || snap.ByProvider["p"].Commission != ^uint64(0) {
		t.Fatalf("commission = %d/%d, want saturated",
			snap.Commission, snap.ByProvider["p"].Commission)
	}

	// Ordinary sums still add.
	l2 := NewLedger()
	l2.NoteSettled("p", 3)
	l2.NoteSettled("p", 4)
	if snap := l2.Snapshot(); snap.Revenue != 7 {
		t.Fatalf("revenue = %d, want 7", snap.Revenue)
	}
}

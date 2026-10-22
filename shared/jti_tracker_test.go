package shared

import (
	"errors"
	"testing"
	"time"
)

func TestJTITracker_AcceptsFirstUseRejectsReplay(t *testing.T) {
	tr := NewJTITracker(0)
	now := time.Unix(1_700_000_000, 0)
	exp := now.Add(60 * time.Second)

	if err := tr.Use("jti-A", exp, now); err != nil {
		t.Fatalf("first use: unexpected err: %v", err)
	}
	if err := tr.Use("jti-A", exp, now.Add(time.Second)); !errors.Is(err, ErrJTIReplayed) {
		t.Fatalf("expected ErrJTIReplayed, got %v", err)
	}
}

func TestJTITracker_AllowsReuseAfterExpiry(t *testing.T) {
	tr := NewJTITracker(0)
	now := time.Unix(1_700_000_000, 0)
	exp := now.Add(60 * time.Second)

	if err := tr.Use("jti-A", exp, now); err != nil {
		t.Fatalf("first use: %v", err)
	}
	// At exactly exp, the prior entry is no longer "before now" — reuse OK.
	if err := tr.Use("jti-A", exp.Add(60*time.Second), exp); err != nil {
		t.Fatalf("post-expiry reuse rejected: %v", err)
	}
}

func TestJTITracker_DistinctJTIs(t *testing.T) {
	tr := NewJTITracker(0)
	now := time.Unix(1_700_000_000, 0)
	exp := now.Add(60 * time.Second)
	for i := range 100 {
		jti := "jti-" + string(rune('A'+i%26)) + string(rune('a'+(i/26)%26))
		if err := tr.Use(jti, exp, now); err != nil {
			t.Fatalf("distinct jti %q rejected: %v", jti, err)
		}
	}
}

func TestJTITracker_LazyGCDropsExpired(t *testing.T) {
	tr := NewJTITracker(0)
	t0 := time.Unix(1_700_000_000, 0)
	exp := t0.Add(10 * time.Second)
	if err := tr.Use("old-jti", exp, t0); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Bump time well past exp + GC window. Second Use triggers GC, drops old.
	if err := tr.Use("new-jti", exp.Add(60*time.Second), t0.Add(2*time.Second)); err != nil {
		t.Fatalf("second use: %v", err)
	}
	if err := tr.Use("third-jti", exp.Add(60*time.Second), t0.Add(20*time.Second)); err != nil {
		t.Fatalf("third use: %v", err)
	}
	if tr.Size() != 2 {
		t.Fatalf("expected 2 entries after GC, got %d", tr.Size())
	}
}

func TestJTITracker_CapacityExceeded(t *testing.T) {
	tr := NewJTITracker(3)
	now := time.Unix(1_700_000_000, 0)
	exp := now.Add(60 * time.Second)
	for i, jti := range []string{"a", "b", "c"} {
		if err := tr.Use(jti, exp, now.Add(time.Duration(i)*time.Microsecond)); err != nil {
			t.Fatalf("fill[%d]: %v", i, err)
		}
	}
	err := tr.Use("d", exp, now)
	if !errors.Is(err, ErrJTICapacityExceeded) {
		t.Fatalf("expected ErrJTICapacityExceeded, got %v", err)
	}
}

func TestJTITracker_EmptyJTIRejected(t *testing.T) {
	tr := NewJTITracker(0)
	if err := tr.Use("", time.Unix(1_700_000_000, 60), time.Unix(1_700_000_000, 0)); err == nil {
		t.Fatal("empty jti accepted")
	}
}

package shared

import (
	"errors"
	"sync"
	"time"
)

// ErrJTIReplayed is returned by JTITracker.Use when the same JTI is
// presented twice before the original JWT's expiry. Callers should
// reject the auth and tear the connection down.
var ErrJTIReplayed = errors.New("allocation JWT replayed (jti already used)")

// ErrJTICapacityExceeded is returned by JTITracker.Use when the cache is
// full of unexpired JTIs and we have no safe entry to evict. Indicates
// load far above the design point or a DoS attempt.
var ErrJTICapacityExceeded = errors.New("jti tracker at capacity; refusing new auth")

// JTITracker is an in-memory replay guard for allocation-JWT IDs.
// Each successful auth inserts its JTI keyed to the JWT's exp; a
// subsequent auth presenting the same JTI before that exp is rejected.
//
// Sized for short-lived JWTs (default 60s exp). At steady state the
// table holds ~peak_qps × jwt_ttl entries. The MaxSize cap caps
// memory at the cost of refusing new auths if exceeded (fail closed).
type JTITracker struct {
	mu       sync.Mutex
	entries  map[string]time.Time // jti -> expiry
	maxSize  int
	lastGCAt time.Time
}

// NewJTITracker returns a tracker with the given size cap. Pass 0 for
// the default cap of 1,048,576 entries (~50 MB worst case).
func NewJTITracker(maxSize int) *JTITracker {
	if maxSize <= 0 {
		maxSize = 1 << 20
	}
	return &JTITracker{
		entries: make(map[string]time.Time),
		maxSize: maxSize,
	}
}

// Use atomically checks-and-inserts a JTI. Returns ErrJTIReplayed if
// the JTI is already present and not yet expired. The provided exp is
// stored verbatim so eviction matches the JWT's lifetime.
//
// Empty jti is treated as a verification failure — a missing JTI means
// the JWT can't be replay-tracked at all. Callers must reject upstream.
func (t *JTITracker) Use(jti string, exp, now time.Time) error {
	if jti == "" {
		return errors.New("jwt: missing jti claim")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Lazy GC at most once per second — bounds scan cost under steady load.
	if now.Sub(t.lastGCAt) > time.Second {
		for k, expAt := range t.entries {
			if !now.Before(expAt) {
				delete(t.entries, k)
			}
		}
		t.lastGCAt = now
	}

	if prevExp, ok := t.entries[jti]; ok {
		if now.Before(prevExp) {
			return ErrJTIReplayed
		}
	}

	if len(t.entries) >= t.maxSize {
		return ErrJTICapacityExceeded
	}

	t.entries[jti] = exp
	return nil
}

// Size returns the current number of tracked entries.
func (t *JTITracker) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

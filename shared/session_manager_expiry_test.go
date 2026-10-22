package shared

import (
	"sync/atomic"
	"testing"
	"time"
)

// cleanupExpiredSessions must fire onSessionExpired once per expired session.
func TestOnSessionExpiredCallback(t *testing.T) {
	sm := NewSessionManager()
	// Force every session to look "stale" immediately. cleanupExpiredSessions
	// will then sweep them on the next tick.
	sm.sessionTimeout = -1 * time.Second

	var callbackCount atomic.Int64
	seen := make(map[string]bool)
	sm.SetOnSessionExpired(func(s *Session) {
		callbackCount.Add(1)
		seen[s.ID] = true
	})

	const N = 5
	created := make([]string, 0, N)
	for range N {
		sid, err := sm.CreateSession(nil)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		// Force the active-branch timeout instead of the 2-min pending one.
		sm.mutex.Lock()
		s := sm.sessions[sid]
		s.State = SessionStateActive
		s.LastActiveAt = time.Now().Add(-1 * time.Hour)
		sm.mutex.Unlock()
		created = append(created, sid)
	}

	sm.cleanupExpiredSessions()

	if got := callbackCount.Load(); got != int64(N) {
		t.Fatalf("callback fired %d times, want %d", got, N)
	}
	for _, sid := range created {
		if !seen[sid] {
			t.Errorf("callback never saw session %s", sid)
		}
	}

	// Sessions should also be gone from the map.
	sm.mutex.Lock()
	leftover := len(sm.sessions)
	sm.mutex.Unlock()
	if leftover != 0 {
		t.Errorf("expected 0 sessions in map after cleanup, got %d", leftover)
	}
}

// Nil callback must not panic.
func TestOnSessionExpiredCallback_NilSafe(t *testing.T) {
	sm := NewSessionManager()
	sm.sessionTimeout = -1 * time.Second

	sid, err := sm.CreateSession(nil)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sm.mutex.Lock()
	s := sm.sessions[sid]
	s.State = SessionStateActive
	s.LastActiveAt = time.Now().Add(-1 * time.Hour)
	sm.mutex.Unlock()

	// Must not panic with no callback registered.
	sm.cleanupExpiredSessions()
}

// Callback must run outside the SessionManager mutex (no re-entry deadlock).
func TestOnSessionExpiredCallback_NoDeadlock(t *testing.T) {
	sm := NewSessionManager()
	sm.sessionTimeout = -1 * time.Second

	sid, err := sm.CreateSession(nil)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sm.mutex.Lock()
	s := sm.sessions[sid]
	s.State = SessionStateActive
	s.LastActiveAt = time.Now().Add(-1 * time.Hour)
	sm.mutex.Unlock()

	done := make(chan struct{})
	sm.SetOnSessionExpired(func(*Session) {
		// If cleanupExpiredSessions still held the mutex this would deadlock.
		_, _ = sm.CreateSession(nil)
		close(done)
	})

	go sm.cleanupExpiredSessions()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("callback deadlocked — mutex not released before invocation")
	}
}

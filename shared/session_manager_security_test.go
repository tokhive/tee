package shared

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestCreateSessionRespectsMaxSessionsUnderConcurrency(t *testing.T) {
	sm := NewSessionManager()
	for i := range MaxSessions - 10 {
		_, err := sm.CreateSession(nil)
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i, err)
		}
	}

	var wg sync.WaitGroup
	var successCount atomic.Int32
	var failCount atomic.Int32

	for range 50 {
		wg.Go(func() {
			_, err := sm.CreateSession(nil)
			if err != nil {
				failCount.Add(1)
			} else {
				successCount.Add(1)
			}
		})
	}
	wg.Wait()

	if successCount.Load() > 10 {
		t.Errorf("expected at most 10 successes, got %d (MaxSessions exceeded)", successCount.Load())
	}
	if successCount.Load()+failCount.Load() != 50 {
		t.Errorf("expected 50 total attempts, got %d", successCount.Load()+failCount.Load())
	}
}

func TestRegisterSessionRejectsDuplicate(t *testing.T) {
	sm := NewSessionManager()
	err := sm.RegisterSession("test-session-1")
	if err != nil {
		t.Fatalf("first register should succeed: %v", err)
	}

	err = sm.RegisterSession("test-session-1")
	if err == nil {
		t.Fatal("second register with same ID should fail")
	}
}

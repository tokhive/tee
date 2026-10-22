//go:build !mobile

package shared

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// fakeHeartbeatTarget is a minimal HeartbeatTarget for unit tests. The
// heartbeat goroutine only reads through the interface, so we don't need
// to construct a full TEEK/TEET.
type fakeHeartbeatTarget struct {
	pairID         string
	router         *RouterClient
	controlHealthy bool
	otReady        bool
	activeSessions int
}

func (f *fakeHeartbeatTarget) PairID() string        { return f.pairID }
func (f *fakeHeartbeatTarget) Router() *RouterClient { return f.router }
func (f *fakeHeartbeatTarget) ControlHealthy() bool  { return f.controlHealthy }
func (f *fakeHeartbeatTarget) OTReady() bool         { return f.otReady }
func (f *fakeHeartbeatTarget) ActiveSessions() int   { return f.activeSessions }

// fakeRouter answers /register and /heartbeat. heartbeat404Until lets a
// test 404 the first N heartbeats to exercise the re-register path.
type fakeRouter struct {
	mu                sync.Mutex
	heartbeats        int
	registers         int
	heartbeat404Until int
}

func (f *fakeRouter) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/register":
			f.registers++
			_ = json.MarshalWrite(w, RegisterResponse{
				PairID: "test-pair", Status: "registering",
			})
		case "/heartbeat":
			f.heartbeats++
			if f.heartbeats <= f.heartbeat404Until {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.MarshalWrite(w, HeartbeatResponse{
				PairID: "test-pair", Status: "degraded",
			})
		default:
			http.Error(w, "unknown path", http.StatusNotFound)
		}
	}
}

func (f *fakeRouter) snapshot() (heartbeats, registers int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heartbeats, f.registers
}

func newFakeRouter(t *testing.T) (*fakeRouter, *RouterClient) {
	t.Helper()
	f := &fakeRouter{}
	srv := httptest.NewTestServer(t, f.handler())
	httpClient := srv.Client()
	tokens := func(_ context.Context, _ string) (string, error) { return "fake", nil }
	router := NewRouterClient(srv.URL, tokens)
	router.httpClient = httpClient
	return f, router
}

func TestRunHeartbeats_SendsPeriodically(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, router := newFakeRouter(t)
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		target := &fakeHeartbeatTarget{pairID: "test-pair", router: router}
		done := make(chan struct{})
		go func() {
			RunHeartbeats(ctx, target, "K", GetTEEKLogger(),
				func(_ context.Context) error { return nil },
				5*time.Millisecond)
			close(done)
		}()

		synctest.Sleep(30 * time.Millisecond)
		cancel()
		synctest.Wait()
		<-done

		hb, regs := f.snapshot()
		if hb < 3 {
			t.Fatalf("expected at least 3 heartbeats in 30ms@5ms, got %d", hb)
		}
		if regs != 0 {
			t.Fatalf("expected no re-registers when heartbeats succeed, got %d", regs)
		}
	})
}

func TestRunHeartbeats_ReregistersOn404(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, router := newFakeRouter(t)
		f.heartbeat404Until = 1
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		var reregisterCalls atomic.Int32
		onLost := func(_ context.Context) error {
			reregisterCalls.Add(1)
			return nil
		}

		target := &fakeHeartbeatTarget{pairID: "test-pair", router: router}
		done := make(chan struct{})
		go func() {
			RunHeartbeats(ctx, target, "K", GetTEEKLogger(), onLost, 5*time.Millisecond)
			close(done)
		}()

		synctest.Sleep(40 * time.Millisecond)
		cancel()
		synctest.Wait()
		<-done

		if got := reregisterCalls.Load(); got != 1 {
			t.Fatalf("expected exactly 1 re-register triggered by 404, got %d", got)
		}
		hb, _ := f.snapshot()
		if hb < 3 {
			t.Fatalf("expected heartbeats to keep firing after 404, got %d", hb)
		}
	})
}

func TestRunHeartbeats_SkipsUntilPairIDKnown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, router := newFakeRouter(t)
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		target := &fakeHeartbeatTarget{pairID: "", router: router} // unknown
		done := make(chan struct{})
		go func() {
			RunHeartbeats(ctx, target, "T", GetTEETLogger(),
				func(_ context.Context) error { return nil },
				5*time.Millisecond)
			close(done)
		}()

		synctest.Sleep(30 * time.Millisecond)
		cancel()
		synctest.Wait()
		<-done

		hb, _ := f.snapshot()
		if hb != 0 {
			t.Fatalf("expected zero heartbeats when pair_id empty, got %d", hb)
		}
	})
}

func TestRunHeartbeats_ContextCancelStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, router := newFakeRouter(t)
		ctx, cancel := context.WithCancel(t.Context())
		target := &fakeHeartbeatTarget{pairID: "p", router: router}
		done := make(chan struct{})
		go func() {
			RunHeartbeats(ctx, target, "K", GetTEEKLogger(),
				func(_ context.Context) error { return nil },
				50*time.Millisecond)
			close(done)
		}()

		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("RunHeartbeats did not return after context cancellation")
		}
	})
}

// noopRATLSRefresher satisfies the rotation surface without touching a device:
// these tests only count how often the loop calls its post-refresh hook.
type noopRATLSRefresher struct{}

func (noopRATLSRefresher) Refresh(context.Context) error { return nil }

// TestRunRATLSRefreshPrimingIsOptional pins the one behavior callers differ on:
// postRefresh runs once before the loop unless the caller says its startup
// already did that work. A cancelled context makes the loop exit immediately
// after the priming call, so the count is deterministic.
func TestRunRATLSRefreshPrimingIsOptional(t *testing.T) {
	tests := []struct {
		name        string
		skipInitial bool
		wantCalls   int
	}{
		{name: "a caller that needs priming gets it", skipInitial: false, wantCalls: 1},
		{name: "a caller that already published is not primed again", skipInitial: true, wantCalls: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			calls := 0
			RunRATLSRefresh(ctx, noopRATLSRefresher{}, func() error {
				calls++
				return nil
			}, nil, nil, NewNopLogger(), test.skipInitial)
			if calls != test.wantCalls {
				t.Fatalf("postRefresh called %d times, want %d", calls, test.wantCalls)
			}
		})
	}
}

func TestExtractIdentityFromRATLS_StandaloneMode(t *testing.T) {
	// Local dev: no launcher socket → RATLSManager produces a cert without
	// the attestation extension. ExtractIdentityFromRATLS must fail clearly,
	// not silently return empty strings.
	ratls, err := NewRATLSManager(t.Context(), "tee_k", nil)
	if err != nil {
		t.Fatalf("new ratls: %v", err)
	}
	logger := GetTEEKLogger()
	defer logger.Sync()

	_, _, _, err = ExtractIdentityFromRATLS(ratls.Snapshot(), logger)
	if err == nil {
		t.Fatal("expected error in standalone mode (no attestation extension)")
	}
}

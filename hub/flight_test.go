package hub

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

// blockingTEE returns a scripted TEE whose FIRST reply blocks until release is
// closed, plus a channel that fires once that reply has been entered. It is how
// these tests hold one job in flight and observe what a second job does.
//
// Only the first call blocks, and that detail is the whole point. What these
// tests assert is a *second* job's fate — refused, or admitted and run while the
// first is still occupied. A fake that held every call would stall that second
// job on the same channel its own release is waiting behind, so the test would
// deadlock (silently, on a channel, at zero CPU) instead of exercising the
// bound. Later calls return at once.
func blockingTEE(t *testing.T, release chan struct{}) (*ScriptedTEE, chan struct{}) {
	t.Helper()
	entered := make(chan struct{}, 1)
	stream := chunks("ok")
	return &ScriptedTEE{Reply: func(call int, _ jobs.Spec) (Result, error) {
		if call == 1 {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
		}
		return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, nil)}, nil
	}}, entered
}

func TestInflightCapRefusesBeyondTheTenantsShare(t *testing.T) {
	release := make(chan struct{})
	fake, entered := blockingTEE(t, release)
	h := mustHub(t, Config{
		TEE:                  fake,
		Rates:                ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
		MaxInflightPerTenant: 1,
	})

	done := make(chan error, 1)
	go func() {
		_, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil)
		done <- err
	}()
	<-entered

	// The tenant's one slot is taken, so a second job is refused outright. It is
	// refused rather than queued on purpose: the bound exists to leave a shared
	// provider's connections for other tenants, not to make this one wait.
	if _, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil); !errors.Is(err, ErrTooManyInflight) {
		t.Fatalf("second job error = %v, want ErrTooManyInflight", err)
	}
	// Refused before dispatch, like every other tenant control: a job that will
	// not run must cost the provider nothing and consume no ProviderSeq.
	if fake.Calls() != 1 {
		t.Fatalf("TEE calls = %d, want 1: the cap must refuse before dispatch", fake.Calls())
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first job: %v", err)
	}
	if got := h.flight.active("tenant"); got != 0 {
		t.Fatalf("in-flight after the job finished = %d, want 0", got)
	}
	if _, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil); err != nil {
		t.Fatalf("job after the first finished: %v", err)
	}
}

func TestInflightCapIsPerTenant(t *testing.T) {
	release := make(chan struct{})
	fake, entered := blockingTEE(t, release)
	h := mustHub(t, Config{
		TEE:                  fake,
		Rates:                ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
		MaxInflightPerTenant: 1,
	})

	done := make(chan error, 1)
	go func() {
		_, err := h.Execute(context.Background(), "alice", "m", testSpec(testProvider, "m"), nil, nil)
		done <- err
	}()
	<-entered

	// alice is at her share; bob is untouched by that. If the cap were global
	// rather than per tenant it would be an outage, not a fairness control.
	if _, err := h.Execute(context.Background(), "bob", "m", testSpec(testProvider, "m"), nil, nil); err != nil {
		t.Fatalf("bob's job: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("alice's job: %v", err)
	}
}

func TestInflightCapDoesNotHoldASlotForARefusedJob(t *testing.T) {
	quota, err := NewQuota(1, time.Minute)
	if err != nil {
		t.Fatalf("quota: %v", err)
	}
	stream := chunks("ok")
	fake := &ScriptedTEE{Reply: func(call int, _ jobs.Spec) (Result, error) {
		return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, nil)}, nil
	}}
	h := mustHub(t, Config{
		TEE:                  fake,
		Rates:                ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
		Quota:                quota,
		MaxInflightPerTenant: 1,
	})

	if _, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil); err != nil {
		t.Fatalf("first job: %v", err)
	}
	// The second job is turned away on rate. It never ran, so the in-flight slot
	// it took on the way in has to come back with it — otherwise one refused
	// call would hold concurrency for as long as its caller's context lives.
	if _, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("second job error = %v, want ErrQuotaExceeded", err)
	}
	if got := h.flight.active("tenant"); got != 0 {
		t.Fatalf("in-flight after a refused job = %d, want 0", got)
	}
	// The third call proves it from the outside: a leaked slot would answer
	// ErrTooManyInflight here, which is checked before the quota is.
	if _, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("third job error = %v, want ErrQuotaExceeded (a leaked slot would report ErrTooManyInflight)", err)
	}
}

func TestSessionHoldsItsSlotUntilItCloses(t *testing.T) {
	fake := &ScriptedTEE{
		Reply: func(call int, _ jobs.Spec) (Result, error) {
			stream := chunks("ok")
			return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, nil)}, nil
		},
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			return &scriptTunnel{rec: sessionReceipt(spec.JobID, 0, nil, 101)}, nil
		},
	}
	h := mustHub(t, Config{
		TEE:                  fake,
		Rates:                ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
		MaxInflightPerTenant: 1,
	})

	conn, _, err := h.OpenSessionForModel(context.Background(), "tenant", "m", buildSession)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	// A session is the job, so it holds the slot for as long as it is open —
	// not merely for the call that opened it. Releasing on return would let a
	// caller run unlimited sessions by opening them in a loop, each holding a
	// provider connection the bound believed was free.
	if _, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil); !errors.Is(err, ErrTooManyInflight) {
		t.Fatalf("job while the session is open = %v, want ErrTooManyInflight", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close session: %v", err)
	}
	if got := h.flight.active("tenant"); got != 0 {
		t.Fatalf("in-flight after the session closed = %d, want 0", got)
	}
	if _, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil); err != nil {
		t.Fatalf("job after the session closed: %v", err)
	}
}

// TestSessionCloseReturnsItsSlotOnce covers the double-close the relay and the
// timeout watchdog both perform: the slot must come back exactly once, and a
// second Close must not give back a slot the tenant never took.
func TestSessionCloseReturnsItsSlotOnce(t *testing.T) {
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			return &scriptTunnel{rec: sessionReceipt(spec.JobID, 0, nil, 101)}, nil
		},
	}
	h := mustHub(t, Config{
		TEE:                  fake,
		Rates:                ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
		MaxInflightPerTenant: 2,
	})

	for i := 0; i < 2; i++ {
		conn, _, err := h.OpenSessionForModel(context.Background(), "tenant", "m", buildSession)
		if err != nil {
			t.Fatalf("open session %d: %v", i, err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("close session %d: %v", i, err)
		}
		// The second close must be a no-op on the books. If it released again it
		// would drive the count below zero and delete the entry, which reads as
		// "idle" while a session is still open.
		_ = conn.Close()
		if got := h.flight.active("tenant"); got != 0 {
			t.Fatalf("in-flight after close #%d = %d, want 0", i, got)
		}
	}
}

func TestNoInflightCapAdmitsEveryJob(t *testing.T) {
	release := make(chan struct{})
	fake, entered := blockingTEE(t, release)
	h := mustHub(t, Config{
		TEE:   fake,
		Rates: ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
	})

	done := make(chan error, 1)
	go func() {
		_, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil)
		done <- err
	}()
	<-entered

	// No limiter configured means no bound, and no bookkeeping table either.
	if h.flight != nil {
		t.Fatalf("an unconfigured Hub built a limiter: %+v", h.flight)
	}
	if _, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil); err != nil {
		t.Fatalf("second job: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first job: %v", err)
	}
}

// --- the limiter on its own -------------------------------------------------

func TestFlightTableForgetsIdleTenants(t *testing.T) {
	f := newFlightLimiter(1, 2)
	for _, tenant := range []string{"a", "b"} {
		if !f.acquire(tenant) {
			t.Fatalf("acquire %q: refused", tenant)
		}
	}
	// The table is full of tenants that are genuinely running, so a third is
	// refused rather than evicting one: an eviction would erase a running
	// tenant's count and hand it a fresh allowance.
	if f.acquire("c") {
		t.Fatalf("acquire into a full table of live tenants was allowed")
	}
	f.release("a")
	if got := f.active("a"); got != 0 {
		t.Fatalf("active(a) = %d, want 0", got)
	}
	// Releasing dropped the entry, so the table has room again — a table that
	// merely holds finished tenants can never fill.
	if !f.acquire("c") {
		t.Fatalf("acquire after a tenant went idle was refused")
	}
}

func TestFlightLimiterIsNilSafe(t *testing.T) {
	var f *flightLimiter
	if !f.acquire("tenant") {
		t.Fatal("a nil limiter refused a job")
	}
	f.release("tenant") // must not panic
	if got := f.active("tenant"); got != 0 {
		t.Fatalf("active on a nil limiter = %d, want 0", got)
	}
}

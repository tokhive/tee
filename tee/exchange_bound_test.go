package tee

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	rootShared "github.com/reclaimprotocol/reclaim-tee/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// The bound on an exchange is the second half of the rotation contract, and the
// half that is easy to lose: refusing a stale epoch keeps a receipt from being
// signed too late, but it does nothing about an exchange admitted in time and
// finishing after the deadline. These tests pin the bound itself, the two
// behaviours it produces — an exchange cut at the deadline still settles, one
// that escapes the bound is not signed — and the cases where it must stay out
// of the way entirely.

// boundTransport records the deadline the service puts on each exchange and can
// behave like a provider that outlives it.
type boundTransport struct {
	mu        sync.Mutex
	requests  []Request
	budgets   []time.Duration
	hasBudget []bool

	// chunks are delivered before the exchange considers ending.
	chunks [][]byte

	// waitForDeadline makes the exchange deliver its chunks and then sit until
	// the context ends, returning the context's error: a provider still holding
	// the connection open when the service's bound fires. With no bound set
	// this blocks forever, which is the point — a test that reaches the return
	// below has proved the exchange was given one.
	waitForDeadline bool

	// onCall runs once at the start of each exchange, before any chunk. Tests
	// use it to move a borrowed clock forward and model an exchange that
	// outlives its bound without the bound being able to stop it — what the
	// check at sign time exists for.
	onCall func()
}

func (b *boundTransport) Do(ctx context.Context, req Request, onChunk func([]byte) error, onStart ...StartFunc) (Response, error) {
	deadline, bounded := ctx.Deadline()
	var budget time.Duration
	if bounded {
		budget = time.Until(deadline)
	}

	b.mu.Lock()
	b.requests = append(b.requests, req)
	b.budgets = append(b.budgets, budget)
	b.hasBudget = append(b.hasBudget, bounded)
	chunks := b.chunks
	onCall := b.onCall
	wait := b.waitForDeadline
	b.mu.Unlock()

	if onCall != nil {
		onCall()
	}

	resp := Response{StatusCode: 200}
	if len(onStart) > 0 && onStart[0] != nil {
		onStart[0](resp)
	}
	for _, chunk := range chunks {
		if onChunk == nil {
			continue
		}
		if err := onChunk(chunk); err != nil {
			return resp, err
		}
	}
	if wait {
		<-ctx.Done()
		return resp, ctx.Err()
	}
	return resp, nil
}

func (b *boundTransport) sent(t *testing.T) []Request {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.requests) == 0 {
		t.Fatal("transport was never called")
	}
	return append([]Request(nil), b.requests...)
}

// budget returns the time left on the exchange's context as the transport saw
// it. The service derives the bound from its own clock while context.WithTimeout
// measures from the wall clock, so the absolute instant is not comparable across
// a pinned test clock; the remaining duration is.
func (b *boundTransport) budget(t *testing.T) time.Duration {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.budgets) == 0 {
		t.Fatal("transport was never called")
	}
	if !b.hasBudget[len(b.hasBudget)-1] {
		t.Fatal("the exchange was given no deadline")
	}
	return b.budgets[len(b.budgets)-1]
}

func withTransport(tr Transport) envOption { return func(c *Config) { c.Transport = tr } }

func withRequestTimeout(d time.Duration) envOption { return func(c *Config) { c.RequestTimeout = d } }

func withClock(now func() time.Time) envOption { return func(c *Config) { c.Clock = now } }

// shiftableClock is a clock a test can move forward, for modelling an exchange
// that outlives the deadline meant to bound it.
type shiftableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *shiftableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *shiftableClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// TestExchangeIsBoundedByTheSigningDeadline pins where the bound sits: the
// signer's signing deadline, less the room a receipt needs to be signed. The
// service's own RequestTimeout is still carried on the request — the bound is
// an addition for the exchange's benefit, not a replacement for the caller's.
func TestExchangeIsBoundedByTheSigningDeadline(t *testing.T) {
	transport := &boundTransport{chunks: [][]byte{[]byte("event: a\n\n")}}
	epoch := epochWithNitroLeaf(t, baseTime.Add(3*time.Hour))
	env := newTestEnv(t,
		withSigner(epoch),
		withTransport(transport),
		withRequestTimeout(90*time.Second),
	)
	body := []byte(`{"model":"m"}`)
	spec := env.spec(t, body)

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if err != nil {
		t.Fatalf("Execute with a fresh epoch = %v, want success", err)
	}

	want := 3*time.Hour - rootShared.SNPSigningMargin - signingHandoff
	got := transport.budget(t)
	if got > want || got < want-time.Second {
		t.Fatalf("exchange had %s left on its context, want %s (the signing deadline less signingHandoff)", got, want)
	}
	if request := transport.sent(t)[0]; request.Timeout != 90*time.Second {
		t.Fatalf("request carried Timeout %s, want the service's own 90s alongside the bound", request.Timeout)
	}
	if string(result.Receipt.Receipt.Attestation.KeyID) != string(epoch.identity.KeyID[:]) {
		t.Fatal("the bounded exchange signed under a different epoch than the one it was pinned to")
	}
}

// TestExchangeCutAtTheBoundStillSettles: an exchange admitted inside the last
// minutes of a leaf is cut at the bound rather than allowed to run past the
// deadline, and what it managed to relay is still attested. That truncation is
// what makes the cut worth having — the receipt names the status and the bytes
// that arrived, which is exactly what the Hub prices, so the provider is paid
// for the work it did instead of the exchange settling nothing.
func TestExchangeCutAtTheBoundStillSettles(t *testing.T) {
	transport := &boundTransport{
		chunks:          [][]byte{[]byte("event: a\n\n")},
		waitForDeadline: true,
	}
	// Two seconds of leaf beyond the signing margin, less the handoff, leaves
	// the exchange one second to run in. A real NitroTPM leaf is second-
	// granularity, so this is as short as a bound can be made without a fake.
	epoch := epochWithNitroLeaf(t, baseTime.Add(rootShared.SNPSigningMargin+2*time.Second))
	env := newTestEnv(t, withSigner(epoch), withTransport(transport))
	body := []byte(`{"model":"m"}`)
	spec := env.spec(t, body)

	start := time.Now()
	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Execute cut at the bound = %v, want a truncated receipt", err)
	}
	if elapsed < 500*time.Millisecond {
		t.Fatalf("the exchange returned in %s, which is too fast to have waited for its bound", elapsed)
	}
	if !result.Truncated {
		t.Fatal("an exchange cut at its bound is reported as complete")
	}
	if got := result.Receipt.Receipt.Completion; got != proof.CompletionTruncated {
		t.Fatalf("receipt completion = %q, want %q", got, proof.CompletionTruncated)
	}
	if result.Receipt.Receipt.StatusCode != 200 || result.ResponseBytes == 0 {
		t.Fatal("the cut receipt does not attest the response that did arrive")
	}
	if string(result.Receipt.Receipt.Attestation.KeyID) != string(epoch.identity.KeyID[:]) {
		t.Fatal("the cut receipt was signed under a different epoch than the one it was bounded by")
	}
}

// TestRefusesWhenThereIsNoRoomToSign: with less than signingHandoff left before
// the deadline, no exchange started now could finish and still be signed inside
// the margin. It is refused the way a stale epoch is — before a sequence number
// or a credential is spent — rather than run into a bound of zero.
func TestRefusesWhenThereIsNoRoomToSign(t *testing.T) {
	transport := &boundTransport{chunks: [][]byte{[]byte("event: a\n\n")}}
	// One second of leaf beyond the margin is exactly signingHandoff, leaving
	// an exchange no room at all.
	epoch := epochWithNitroLeaf(t, baseTime.Add(rootShared.SNPSigningMargin+time.Second))
	env := newTestEnv(t, withSigner(epoch), withTransport(transport))
	body := []byte(`{"model":"m"}`)
	spec := env.spec(t, body)

	start := time.Now()
	_, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if !errors.Is(err, ErrAttestationStale) {
		t.Fatalf("Execute with no room before the deadline = %v, want %v", err, ErrAttestationStale)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the refusal took %s, want an immediate one rather than an exchange that ran into its bound", elapsed)
	}
	if len(transport.requests) != 0 {
		t.Fatal("a job with no room to be signed reached the provider transport")
	}
	if seq, err := env.service.seq.Next([]byte("openai")); err != nil || seq != 1 {
		t.Fatalf("refused job consumed sequence (next = %d, err = %v), want the series untouched", seq, err)
	}
}

// TestReceiptIsNotSignedAfterTheDeadline is the fail-safe. The bound is what
// normally keeps an execution inside the margin, but it is a deadline rather
// than a guarantee: a transport that ignores its context, or a clock that jumps,
// still reaches the signature. Then the work is abandoned — a receipt citing
// evidence past its margin is refused by every verifier, which is worse than no
// receipt, because it looks like evidence and is settled like evidence until
// somebody checks the leaf.
func TestReceiptIsNotSignedAfterTheDeadline(t *testing.T) {
	clock := &shiftableClock{now: baseTime}
	transport := &boundTransport{
		chunks: [][]byte{[]byte("event: a\n\n")},
		// The exchange runs past the signer's deadline without the bound being
		// able to stop it: it returns a complete response, having advanced the
		// clock beyond the instant the receipt may still be signed at.
		onCall: func() { clock.Advance(10 * time.Second) },
	}
	epoch := epochWithNitroLeaf(t, baseTime.Add(rootShared.SNPSigningMargin+3*time.Second))
	env := newTestEnv(t, withSigner(epoch), withTransport(transport), withClock(clock.Now))
	body := []byte(`{"model":"m"}`)
	spec := env.spec(t, body)

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if !errors.Is(err, ErrAttestationStale) {
		t.Fatalf("Execute that outlived the deadline = %v, want %v", err, ErrAttestationStale)
	}
	if result != nil {
		t.Fatal("a receipt was returned for an exchange that outlived its evidence")
	}
	if len(transport.sent(t)) != 1 {
		t.Fatal("the exchange did not reach the provider, so this test is not exercising the fail-safe")
	}
}

// TestUntrackedEvidenceLeavesTheContextAlone: evidence with no readable
// NitroTPM leaf carries no deadline to bound against, so the caller's own
// context stays the only bound. Without this the gate would have to invent a
// deadline for the simulation and every pinned test clock would look like an
// outage.
func TestUntrackedEvidenceLeavesTheContextAlone(t *testing.T) {
	transport := &boundTransport{chunks: [][]byte{[]byte("event: a\n\n")}}
	env := newTestEnv(t, withTransport(transport))
	body := []byte(`{"model":"m"}`)

	if _, err := env.service.Execute(context.Background(), Job{Spec: env.spec(t, body), Body: body}, nil); err != nil {
		t.Fatalf("Execute on untracked evidence = %v, want success", err)
	}
	if bounded := transport.hasBudget[0]; bounded {
		t.Fatal("an unreadable leaf produced a deadline out of nothing")
	}

	// And a bound the caller set themselves passes through untouched.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := env.service.Execute(ctx, Job{Spec: env.spec(t, body), Body: body}, nil); err != nil {
		t.Fatalf("Execute under a caller's deadline = %v, want success", err)
	}
	if got := transport.budget(t); got > 30*time.Second || got < 25*time.Second {
		t.Fatalf("exchange had %s left of the caller's own 30s deadline", got)
	}
}

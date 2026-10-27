package hub

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/tokhive/tee/jobs"
	"github.com/tokhive/tee/proof"
)

// These tests exercise the streaming-session engine — provider selection, byte
// relay, and settlement under the Hub's own bounds — against scripted tunnels,
// with no network and no real TEE. They cover what a request/response test
// cannot: a receipt whose bytes and hash must match what the relay actually
// moved, a session the TEE cut at the cap both sides agreed on (which settles
// for what it delivered), and a session the TEE overran (which settles
// nothing, because no receipt can support a charge).
//
// Every receipt is built inside the OpenReply closure from the spec the Hub
// dispatched — spec.JobID is the same value relaySession hashes with, so a
// receipt that disagrees with the relay is a genuine mismatch, not a test bug.

// scriptTunnel is the session stand-in behind ScriptedTEE.OpenReply. It emits a
// fixed downlink frame sequence and reports a precomputed receipt.
type scriptTunnel struct {
	mu     sync.Mutex
	frames [][]byte
	rec    proof.SignedReceipt
	up     uint64
	next   int
}

func (t *scriptTunnel) Read(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.next >= len(t.frames) {
		return 0, io.EOF
	}
	n := copy(p, t.frames[t.next])
	if n < len(t.frames[t.next]) {
		t.frames[t.next] = t.frames[t.next][n:]
		return n, nil
	}
	t.next++
	return n, nil
}

func (t *scriptTunnel) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.up += uint64(len(p))
	return len(p), nil
}

func (t *scriptTunnel) Close() error { return nil }
func (t *scriptTunnel) Uplink() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.up
}

func (t *scriptTunnel) Receipt() (proof.SignedReceipt, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.rec, nil
}

// blockTunnel never emits a frame and unblocks its Read only when closed — the
// only thing that can end a session over it is a Hub bound.
type blockTunnel struct {
	once   sync.Once
	closed chan struct{}
}

func (t *blockTunnel) Read(p []byte) (int, error) {
	<-t.closed
	return 0, errors.New("tunnel closed")
}
func (t *blockTunnel) Write(p []byte) (int, error) { return len(p), nil }
func (t *blockTunnel) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}
func (t *blockTunnel) Receipt() (proof.SignedReceipt, error) {
	return proof.SignedReceipt{}, errors.New("session receipt not yet available")
}

// sessionReceipt builds a SessionConn receipt for the downlink frames a tunnel
// emitted, attesting StatusCode 101 and the exact uplink/downlink tallies
// RunRealtime checks before settling.
func sessionReceipt(jobID []byte, up uint64, down [][]byte, status uint32) proof.SignedReceipt {
	return sessionReceiptState(jobID, up, down, status, proof.CompletionComplete)
}

// sessionReceiptState is sessionReceipt with an explicit completion state, so a
// test can model a TEE that cut the session at its cap (CompletionTruncated)
// rather than one whose provider finished the stream.
func sessionReceiptState(jobID []byte, up uint64, down [][]byte, status uint32, completion proof.CompletionState) proof.SignedReceipt {
	var downBytes uint64
	for _, f := range down {
		downBytes += uint64(len(f))
	}
	r := proof.Receipt{
		Version:       proof.VersionV1,
		JobID:         jobID,
		Provider:      testProvider,
		StatusCode:    status,
		Completion:    completion,
		ChunkCount:    uint64(len(down)),
		ResponseBytes: downBytes,
		RequestBytes:  up,
	}
	r = ScriptReceipt(down, r)
	return proof.SignedReceipt{Receipt: r}
}

// userLink is the non-network side of the tunnel: down holds what the relay
// delivered to the user side, up feeds the user-side frame stream.
type userLink struct {
	down bytes.Buffer
	up   bytes.Buffer
}

func (l *userLink) Write(p []byte) (int, error) { return l.down.Write(p) }
func (l *userLink) Read(p []byte) (int, error)  { return l.up.Read(p) }

// addUp streams a frame into the user-side uplink, which relaySession forwards
// through the tunnel (and which the tunnel metes as RequestBytes).
func (l *userLink) addUp(s string) { l.up.WriteString(s) }

// openSessionSpec frames a session job for a provider, mirroring what a
// realtime entry would build. It carries a downlink cap exactly as the real
// builder does, so the tests exercise the same tightening the Hub applies.
func openSessionSpec(provider string) jobs.Spec {
	return jobs.Spec{
		Version:          jobs.VersionV1,
		JobID:            make([]byte, proof.JobIDLength),
		Provider:         provider,
		Method:           "GET",
		Host:             "provider.test:443",
		Path:             "/v1/realtime",
		Stream:           true,
		Session:          true,
		MaxResponseBytes: 1 << 20,
	}
}

// buildSession is the `build` closure OpenSessionForModel expects: identical
// framing across providers, only the provider name changes.
func buildSession(provider string) (jobs.Spec, error) {
	return openSessionSpec(provider), nil
}

func TestOpenSessionForModelPicksCheapestAndFailsOver(t *testing.T) {
	tried := map[string]bool{}
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			tried[spec.Provider] = true
			// "cheap" is tried first and fails; the Hub fails over to "dear"
			// rather than giving up, exactly as ExecuteForModel does.
			if spec.Provider == "cheap" {
				return nil, errors.New("open refused")
			}
			return &scriptTunnel{rec: sessionReceipt(spec.JobID, 0, nil, 101)}, nil
		},
	}
	h := mustHub(t, Config{
		TEE: fake,
		Rates: ratesTable(map[string]RateCard{
			"cheap": {PerRequestMicros: 100},
			"dear":  {PerRequestMicros: 900},
		}),
	})

	conn, spec, err := h.OpenSessionForModel(context.Background(), "tenant", "m", buildSession)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	defer conn.Close()
	if spec.Provider != "dear" {
		t.Fatalf("provider = %q, want cheapest that opened (dear)", spec.Provider)
	}
	if !tried["cheap"] {
		t.Fatalf("cheapest provider was never tried")
	}
}

func TestRunRealtimeRefusesAboveCeiling(t *testing.T) {
	// A card whose book price (per-request + one MiB of volume = 400) fits the
	// ceiling, but whose volume rate pushes the real bill past it once the
	// provider streams 3 MiB (3 units => 900 + 100 = 1000). The candidate
	// filter cannot catch this — only the settlement-time backstop can.
	card := RateCard{PerRequestMicros: 100, PerMegabyteMicros: 300}

	mib := bytes.Repeat([]byte("x"), 1<<20)
	down := [][]byte{mib, mib, mib}
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			return &scriptTunnel{frames: down, rec: sessionReceipt(spec.JobID, 0, down, 101)}, nil
		},
	}
	store := NewReceiptStore(t.TempDir())
	h, err := New(Config{
		TEE:          fake,
		Rates:        ratesTable(map[string]RateCard{testProvider: card}),
		Store:        store,
		Verify:       acceptAll,
		MaxJobMicros: 500,
	})
	if err != nil {
		t.Fatalf("build hub: %v", err)
	}

	outcome, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, &userLink{})
	if !errors.Is(err, ErrJobPriceExceeded) {
		t.Fatalf("err = %v, want ErrJobPriceExceeded", err)
	}
	if outcome.Charged != 1_000 {
		t.Errorf("charged = %d, want the priced 1000 (3 MiB + fee)", outcome.Charged)
	}
	if !outcome.Stored {
		t.Error("session receipt must be stored even when the ceiling refuses payment")
	}
	if snap := h.Ledger().Snapshot(); snap.Settled != 0 || snap.Revenue != 0 {
		t.Errorf("ledger settled/revenue = %d/%d, want 0/0", snap.Settled, snap.Revenue)
	}
}

func TestRunRealtimeSettlesASession(t *testing.T) {
	down := [][]byte{[]byte("data"), []byte(": {}\n"), []byte("\n")}
	var tunnel *scriptTunnel
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			tunnel = &scriptTunnel{frames: down, rec: sessionReceipt(spec.JobID, 0, down, 101)}
			return tunnel, nil
		},
	}
	h := mustHub(t, Config{
		TEE:   fake,
		Rates: ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 250}}),
	})
	link := &userLink{}

	outcome, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, link)
	if err != nil {
		t.Fatalf("run realtime: %v", err)
	}
	if outcome.Provider != testProvider {
		t.Fatalf("provider = %q", outcome.Provider)
	}
	if got := link.down.String(); got != "data: {}\n\n" {
		t.Fatalf("downlink bytes = %q", got)
	}
	if outcome.Charged != 250 {
		t.Fatalf("charged = %d, want 250", outcome.Charged)
	}
	if !outcome.Stored {
		t.Fatalf("session receipt not stored")
	}
	if tunnel.Uplink() != 0 {
		t.Fatalf("unexpected uplink %d", tunnel.Uplink())
	}
}

func TestRunRealtimeCountsUplinkAndDownlink(t *testing.T) {
	down := [][]byte{[]byte("hello, "), []byte("provider")}
	up := uint64(len("config:first\n"))
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			return &scriptTunnel{frames: down, rec: sessionReceipt(spec.JobID, up, down, 101)}, nil
		},
	}
	h := mustHub(t, Config{
		TEE:   fake,
		Rates: ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
	})
	link := &userLink{}
	link.addUp("config:first\n")

	outcome, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, link)
	if err != nil {
		t.Fatalf("run realtime: %v", err)
	}
	if outcome.UplinkBytes != up {
		t.Fatalf("uplink = %d, want %d", outcome.UplinkBytes, up)
	}
	if outcome.DownlinkBytes != uint64(len(down[0])+len(down[1])) {
		t.Fatalf("downlink = %d", outcome.DownlinkBytes)
	}
}

func TestRunRealtimeRejectsStreamMismatch(t *testing.T) {
	down := [][]byte{[]byte("real")}
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			// Same job, but the receipt attests bytes the tunnel never emitted.
			return &scriptTunnel{frames: down, rec: sessionReceipt(spec.JobID, 0, [][]byte{[]byte("forged")}, 101)}, nil
		},
	}
	h := mustHub(t, Config{
		TEE:   fake,
		Rates: ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
	})

	_, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, &userLink{})
	if !errors.Is(err, ErrSessionStreamMismatch) {
		t.Fatalf("err = %v, want ErrSessionStreamMismatch", err)
	}
}

func TestRunRealtimeSettlesASessionTheTEECutAtItsCap(t *testing.T) {
	// The whole point of carrying the cap on the spec: the TEE stops at the
	// same number the Hub does, delivers and digests only that prefix, and the
	// receipt therefore reconciles with what the Hub relayed. The session is
	// then priced like any other truncated stream — volume for the bytes that
	// arrived, no flat fee for the ones that did not — instead of earning
	// nothing at all.
	//
	// Frames the provider sent past the cap are not modelled here: the TEE is
	// the component that cuts, so "what the tunnel emits" already is the
	// delivered prefix. What this test pins is that the Hub bills it.
	delivered := [][]byte{[]byte("data: "), []byte("{}\n\n")}
	deliveredBytes := uint64(len(delivered[0]) + len(delivered[1]))

	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			if spec.MaxResponseBytes != deliveredBytes {
				return nil, fmt.Errorf("spec cap = %d, want the Hub's bound %d", spec.MaxResponseBytes, deliveredBytes)
			}
			return &scriptTunnel{
				frames: delivered,
				rec:    sessionReceiptState(spec.JobID, 0, delivered, 101, proof.CompletionTruncated),
			}, nil
		},
	}
	h := mustHub(t, Config{
		TEE:                 fake,
		SessionMaxDownBytes: deliveredBytes,
		Rates: ratesTable(map[string]RateCard{
			testProvider: {PerRequestMicros: 500_000, PerMegabyteMicros: 2_000_000},
		}),
	})
	link := &userLink{}

	outcome, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, link)
	if err != nil {
		t.Fatalf("run realtime: %v (a session cut at its cap must settle)", err)
	}
	if got := link.down.String(); got != "data: {}\n\n" {
		t.Fatalf("downlink to the user = %q, want the delivered prefix", got)
	}
	if outcome.DownlinkBytes != deliveredBytes {
		t.Fatalf("downlink = %d, want %d", outcome.DownlinkBytes, deliveredBytes)
	}
	if outcome.Charged != 2_000_000 {
		t.Fatalf("charged = %d, want one mebibyte of volume and no flat fee (truncated)", outcome.Charged)
	}
	if outcome.Buyer != 2_000_000 {
		t.Fatalf("buyer = %d, want the charge alone (no commission configured)", outcome.Buyer)
	}
	if !outcome.Stored {
		t.Fatal("a truncated-but-reconciled session must still store its receipt")
	}
}

func TestRunRealtimeByteCapTruncatesNotSettled(t *testing.T) {
	// The Hub's own bound is a backstop, not the operative cap: normally the
	// TEE cuts first and the session settles (see the test above). This is the
	// case it exists for — a TEE that relays past the cap its own spec declared.
	// Its digest then covers bytes the Hub never moved, and because the response
	// digest is a plain hash rather than a prefix-verifiable one, nothing it
	// signs can be matched to the relayed transcript. Nothing settles, and the
	// Hub reports the bound that fired.
	down := [][]byte{[]byte("first"), []byte("second")}
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			return &scriptTunnel{frames: down, rec: sessionReceipt(spec.JobID, 0, down, 101)}, nil
		},
	}
	h := mustHub(t, Config{
		TEE:                 fake,
		SessionMaxDownBytes: uint64(len(down[0]) + 1), // relays the first frame only
		Rates:               ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
	})

	outcome, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, &userLink{})
	if !errors.Is(err, ErrSessionLimitExceeded) {
		t.Fatalf("err = %v, want ErrSessionLimitExceeded", err)
	}
	if outcome.DownlinkBytes != uint64(len(down[0])) {
		t.Fatalf("downlink = %d, want only first frame (%d) relayed", outcome.DownlinkBytes, len(down[0]))
	}
	// No receipt can be reconciled against a TEE that broke its bound, so
	// nothing is charged and nothing is stored.
	if outcome.Stored {
		t.Fatalf("a session the TEE overran must not store a receipt")
	}
	if outcome.Charged != 0 {
		t.Fatalf("charged = %d, want 0 when no receipt supports the charge", outcome.Charged)
	}
}

// TestBoundSessionTightensButNeverWidens pins the alignment rule: the Hub may
// only lower a session's declared cap, because raising it past the provider
// policy's own limit makes the TEE refuse the job outright.
func TestBoundSessionTightensButNeverWidens(t *testing.T) {
	fake := &ScriptedTEE{}
	h := mustHub(t, Config{
		TEE:                 fake,
		Rates:               ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 1}}),
		SessionMaxDownBytes: 1000,
	})

	cases := []struct {
		name string
		in   uint64
		want uint64
	}{
		{"a caller cap below the Hub's stands", 500, 500},
		{"a caller cap above the Hub's is lowered", 5000, 1000},
		{"an unset caller cap takes the Hub's", 0, 1000},
	}
	for _, c := range cases {
		if got := h.boundSession(jobs.Spec{MaxResponseBytes: c.in}).MaxResponseBytes; got != c.want {
			t.Errorf("%s: cap = %d, want %d", c.name, got, c.want)
		}
	}

	// With no Hub bound the caller's cap is all there is, untouched.
	unbounded := mustHub(t, Config{
		TEE:   fake,
		Rates: ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 1}}),
	})
	if got := unbounded.boundSession(jobs.Spec{MaxResponseBytes: 7}).MaxResponseBytes; got != 7 {
		t.Errorf("with no Hub bound the caller's cap must stand, got %d", got)
	}
}

func TestRunRealtimeSettlesUplinkTeardownTail(t *testing.T) {
	// The Hub relays one uplink frame, but the receipt attests none of it —
	// exactly the session-end race where the user's final bytes are counted by
	// the Hub while the tunnel is already closed, so they never reach the TEE.
	// The receipt is still the attested record of what was delivered, so the
	// session must settle rather than forfeit.
	down := [][]byte{[]byte("data: {}\n\n")}
	up := uint64(len("config:first\n"))
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			return &scriptTunnel{frames: down, rec: sessionReceipt(spec.JobID, 0, down, 101)}, nil
		},
	}
	h := mustHub(t, Config{
		TEE:   fake,
		Rates: ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
	})
	link := &userLink{}
	link.addUp("config:first\n")

	outcome, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, link)
	if err != nil {
		t.Fatalf("run realtime: %v (a teardown tail must not forfeit the session)", err)
	}
	if !outcome.Stored {
		t.Fatalf("receipt not stored for a settled session")
	}
	// Billing follows the receipt: the buyer pays for what the TEE attested
	// was delivered (the flat fee here), not for the tail the Hub counted.
	if outcome.Charged != 100 {
		t.Errorf("charged = %d, want 100", outcome.Charged)
	}
	// The Hub still reports what it observed, even when it exceeds the receipt.
	if outcome.UplinkBytes != up {
		t.Errorf("uplink reported = %d, want %d (the Hub's own count)", outcome.UplinkBytes, up)
	}
}

func TestRunRealtimeRejectsInflatedUplink(t *testing.T) {
	// The fraud direction: the receipt attests more uplink than the Hub ever
	// relayed. The Hub counts every byte before writing it, so a receipt
	// beyond that bound describes an exchange that did not happen — refusing
	// it is what protects the buyer from an inflated bill.
	down := [][]byte{[]byte("data: {}\n\n")}
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			return &scriptTunnel{frames: down, rec: sessionReceipt(spec.JobID, 999, down, 101)}, nil
		},
	}
	h := mustHub(t, Config{
		TEE:   fake,
		Rates: ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
	})

	_, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, &userLink{})
	if !errors.Is(err, ErrSessionStreamMismatch) {
		t.Fatalf("err = %v, want ErrSessionStreamMismatch", err)
	}
}

func TestRunRealtimeQuotaBlocksBeforeOpen(t *testing.T) {
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			return &scriptTunnel{rec: sessionReceipt(spec.JobID, 0, nil, 101)}, nil
		},
	}
	q, err := NewQuota(1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	q.Allow("tenant", time.Now()) // consume the only slot in the window
	h := mustHub(t, Config{
		TEE:   fake,
		Quota: q,
		Rates: ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
	})

	if _, _, err := h.OpenSessionForModel(context.Background(), "tenant", "m", buildSession); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("err = %v, want ErrQuotaExceeded", err)
	}
	if fake.OpenCalls() != 0 {
		t.Fatalf("session opened %d times despite quota, want 0", fake.OpenCalls())
	}
}

func TestRunRealtimeTimeoutEndsASession(t *testing.T) {
	// A tunnel that never emits a frame: only the Hub's wall-clock bound can end
	// the session. The tunnel never produces a receipt, so the settle it can't
	// finish surfaces as ErrNoReceiptForSession — the important assertion is that
	// the Hub stops waiting.
	fake := &ScriptedTEE{
		OpenReply: func(_ int, _ jobs.Spec) (SessionConn, error) {
			return &blockTunnel{closed: make(chan struct{})}, nil
		},
	}
	h := mustHub(t, Config{
		TEE:            fake,
		SessionTimeout: 50 * time.Millisecond,
		Rates:          ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
	})

	done := make(chan error, 1)
	go func() {
		_, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, &userLink{})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNoReceiptForSession) {
			t.Fatalf("err = %v, want ErrNoReceiptForSession from an ended, unsettled session", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("hub did not enforce the session timeout")
	}
}

// TestRunRealtimeStopsUplinkAtTheBound pins the uplink byte bound: a user that
// uploads more than the Hub will relay must have the excess dropped, not
// forwarded into the provider's tunnel. The TEE applies no session bound of its
// own (it is a transparent relay), so this is the Hub's only protection against
// an unbounded upload.
func TestRunRealtimeStopsUplinkAtTheBound(t *testing.T) {
	down := [][]byte{[]byte("ok")}
	var tunnel *scriptTunnel
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			tunnel = &scriptTunnel{frames: down, rec: sessionReceipt(spec.JobID, 0, down, 101)}
			return tunnel, nil
		},
	}
	h := mustHub(t, Config{
		TEE:               fake,
		Rates:             ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
		SessionMaxUpBytes: 4,
	})
	link := &userLink{}
	link.addUp("far more than four bytes")

	outcome, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, link)
	if err != nil {
		t.Fatalf("run realtime: %v", err)
	}
	if outcome.UplinkBytes != 0 {
		t.Fatalf("uplink counted = %d, want 0 (the over-bound chunk must not be relayed)", outcome.UplinkBytes)
	}
	if tunnel.Uplink() != 0 {
		t.Fatalf("uplink relayed = %d, want 0", tunnel.Uplink())
	}
}

// closingLink is a user link that can be told to end, so a test can pin that
// the Hub's own bound produced a graceful close rather than a silent hang-up.
type closingLink struct {
	userLink
	mu     sync.Mutex
	reason string
}

func (l *closingLink) CloseSession(reason string) {
	l.mu.Lock()
	l.reason = reason
	l.mu.Unlock()
}

func (l *closingLink) closeReason() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reason
}

// TestRunRealtimeClosesTheUserAtTheUplinkBound pins the graceful half of the
// bound: the link is told to close, which is what sends the provider a close
// frame and keeps the receipt obtainable. Simply abandoning the read would
// leave the provider streaming into a tunnel nobody drains.
func TestRunRealtimeClosesTheUserAtTheUplinkBound(t *testing.T) {
	down := [][]byte{[]byte("ok")}
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			return &scriptTunnel{frames: down, rec: sessionReceipt(spec.JobID, 0, down, 101)}, nil
		},
	}
	h := mustHub(t, Config{
		TEE:               fake,
		Rates:             ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
		SessionMaxUpBytes: 4,
	})
	link := &closingLink{}
	link.addUp("far more than four bytes")

	if _, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, link); err != nil {
		t.Fatalf("run realtime: %v", err)
	}
	if link.closeReason() == "" {
		t.Fatal("the uplink bound did not close the user side")
	}
}

// gatedTunnel is a session tunnel whose provider end finishes only when the
// test releases it. It distinguishes "the session was allowed to finish" from
// "the Hub closed the tunnel the moment the user hung up": a close before the
// release makes Read fail, and only a read that reached its clean EOF has a
// receipt.
type gatedTunnel struct {
	mu       sync.Mutex
	frames   [][]byte
	up       uint64
	finished bool
	rec      proof.SignedReceipt
	release  chan struct{}
	done     chan struct{}
	once     sync.Once
}

func (t *gatedTunnel) Read(p []byte) (int, error) {
	t.mu.Lock()
	if len(t.frames) > 0 {
		n := copy(p, t.frames[0])
		if n == len(t.frames[0]) {
			t.frames = t.frames[1:]
		} else {
			t.frames[0] = t.frames[0][n:]
		}
		t.mu.Unlock()
		return n, nil
	}
	t.mu.Unlock()
	select {
	case <-t.release:
		t.mu.Lock()
		t.finished = true
		t.mu.Unlock()
		return 0, io.EOF
	case <-t.done:
		return 0, errors.New("tunnel closed before the provider finished")
	}
}

func (t *gatedTunnel) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.up += uint64(len(p))
	return len(p), nil
}

func (t *gatedTunnel) Close() error {
	t.once.Do(func() { close(t.done) })
	return nil
}

func (t *gatedTunnel) Closed() bool {
	select {
	case <-t.done:
		return true
	default:
		return false
	}
}

func (t *gatedTunnel) Receipt() (proof.SignedReceipt, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.finished {
		return proof.SignedReceipt{}, errors.New("session receipt not yet available")
	}
	return t.rec, nil
}

// TestRunRealtimeSettlesWhenTheUserClosesFirst is the billing-critical case: a
// user who hangs up first must not forfeit the session. The provider is still
// streaming when the uplink ends, and the Hub has to let it finish so the TEE
// can sign the receipt. Closing the tunnel the instant the uplink ended — the
// old behavior — aborts that read and settles nothing.
func TestRunRealtimeSettlesWhenTheUserClosesFirst(t *testing.T) {
	down := [][]byte{[]byte("data: {}\n\n")}
	opened := make(chan *gatedTunnel, 1)
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			tunnel := &gatedTunnel{
				frames:  down,
				rec:     sessionReceipt(spec.JobID, 0, down, 101),
				release: make(chan struct{}),
				done:    make(chan struct{}),
			}
			opened <- tunnel
			return tunnel, nil
		},
	}
	h := mustHub(t, Config{
		TEE:   fake,
		Rates: ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
	})

	type result struct {
		outcome SessionOutcome
		err     error
	}
	done := make(chan result, 1)
	go func() {
		outcome, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, &userLink{})
		done <- result{outcome, err}
	}()

	tunnel := <-opened
	// The user link is empty and ends at once. Give the relay time to observe
	// that, then assert the tunnel is still open: the provider, not the user,
	// ends the session, and closing it here would forfeit the receipt.
	time.Sleep(150 * time.Millisecond)
	if tunnel.Closed() {
		t.Fatal("the Hub closed the tunnel when the user hung up instead of waiting for the provider")
	}
	close(tunnel.release)

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("run realtime: %v", r.err)
		}
		if !r.outcome.Stored {
			t.Fatal("a session closed by its user must still settle")
		}
		if r.outcome.DownlinkBytes != uint64(len(down[0])) {
			t.Fatalf("downlink = %d, want %d relayed before the close", r.outcome.DownlinkBytes, len(down[0]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the session did not finish after the provider closed")
	}
}

// blockedLink keeps its uplink open until the Hub ends the session, and records
// the close it was asked to send. That lets a test separate a Hub-imposed
// ending (a timeout or the idle watchdog) from the user hanging up first.
type blockedLink struct {
	userLink
	hold   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	reason string
}

func newBlockedLink() *blockedLink { return &blockedLink{hold: make(chan struct{})} }

func (l *blockedLink) Read(p []byte) (int, error) {
	<-l.hold
	return 0, io.EOF
}

func (l *blockedLink) CloseSession(reason string) {
	l.mu.Lock()
	if l.reason == "" {
		l.reason = reason
	}
	l.mu.Unlock()
	l.once.Do(func() { close(l.hold) })
}

func (l *blockedLink) closeReason() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reason
}

// TestRunRealtimeSettlesAfterItsTimeoutWhenTheLinkCanClose pins the graceful
// half of the wall-clock bound: the Hub must not cut the tunnel the instant the
// deadline fires, because the provider's answer to the link's close is what
// lets the TEE sign. Cutting it would forfeit a session that had already
// delivered bytes. A link that cannot close is still cut, which
// TestRunRealtimeTimeoutEndsASession covers.
func TestRunRealtimeSettlesAfterItsTimeoutWhenTheLinkCanClose(t *testing.T) {
	down := [][]byte{[]byte("data: {}\n\n")}
	opened := make(chan *gatedTunnel, 1)
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			tunnel := &gatedTunnel{
				frames:  down,
				rec:     sessionReceipt(spec.JobID, 0, down, 101),
				release: make(chan struct{}),
				done:    make(chan struct{}),
			}
			opened <- tunnel
			return tunnel, nil
		},
	}
	h := mustHub(t, Config{
		TEE:            fake,
		Rates:          ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
		SessionTimeout: 100 * time.Millisecond,
	})
	link := newBlockedLink()

	type result struct {
		outcome SessionOutcome
		err     error
	}
	done := make(chan result, 1)
	go func() {
		outcome, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, link)
		done <- result{outcome, err}
	}()

	tunnel := <-opened
	// Wait past the timeout, then check both halves of the contract: the Hub
	// asked the link to close instead of hanging up on it, and it has left the
	// tunnel open while the provider can still answer that close.
	time.Sleep(300 * time.Millisecond)
	if got := link.closeReason(); got != "session ended" {
		t.Fatalf("close reason = %q, want the timeout to close both ends", got)
	}
	if tunnel.Closed() {
		t.Fatal("the Hub cut the tunnel at the timeout instead of letting the provider answer the close")
	}
	close(tunnel.release)

	select {
	case r := <-done:
		if !errors.Is(r.err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want the timeout reported alongside the settled outcome", r.err)
		}
		if !r.outcome.Stored {
			t.Fatal("a session ended by its timeout must still settle for the bytes it delivered")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the session did not finish after the provider answered the close")
	}
}

// TestRunRealtimeSettlesAfterAnIdleStallWhenTheLinkCanClose is the same contract
// for the downlink-stall watchdog: a provider that goes quiet must be answered
// with a close and given the grace to finish, not have its tunnel yanked out
// from under a receipt it was about to sign.
func TestRunRealtimeSettlesAfterAnIdleStallWhenTheLinkCanClose(t *testing.T) {
	down := [][]byte{[]byte("data: {}\n\n")}
	opened := make(chan *gatedTunnel, 1)
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			tunnel := &gatedTunnel{
				frames:  down,
				rec:     sessionReceipt(spec.JobID, 0, down, 101),
				release: make(chan struct{}),
				done:    make(chan struct{}),
			}
			opened <- tunnel
			return tunnel, nil
		},
	}
	h := mustHub(t, Config{
		TEE:         fake,
		Rates:       ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
		SessionIdle: 50 * time.Millisecond,
	})
	link := newBlockedLink()

	type result struct {
		outcome SessionOutcome
		err     error
	}
	done := make(chan result, 1)
	go func() {
		outcome, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, link)
		done <- result{outcome, err}
	}()

	tunnel := <-opened
	time.Sleep(200 * time.Millisecond)
	if got := link.closeReason(); got != "provider went idle" {
		t.Fatalf("close reason = %q, want the idle watchdog to close both ends", got)
	}
	if tunnel.Closed() {
		t.Fatal("the idle watchdog cut the tunnel instead of letting the provider answer the close")
	}
	close(tunnel.release)

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("run realtime: %v", r.err)
		}
		if !r.outcome.Stored {
			t.Fatal("a session ended by the idle watchdog must still settle for the bytes it delivered")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the session did not finish after the provider answered the close")
	}
}

// handshakeTunnel adds the provider's selected subprotocol to a scripted
// tunnel, as the real sessionTunnel does.
type handshakeTunnel struct {
	SessionConn
	proto string
}

func (t *handshakeTunnel) Subprotocol() string { return t.proto }

// protocolLink states the subprotocol the user negotiated.
type protocolLink struct {
	userLink
	proto string
}

func (l *protocolLink) Subprotocol() string { return l.proto }

// TestRunRealtimeRefusesSubprotocolMismatch pins the handshake honesty rule: the
// Hub answered the user's Upgrade with one subprotocol, so it must not relay a
// provider that selected another. The refusal happens before any tunnel byte
// moves.
func TestRunRealtimeRefusesSubprotocolMismatch(t *testing.T) {
	down := [][]byte{[]byte("must not reach the user")}
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			return &handshakeTunnel{
				SessionConn: &scriptTunnel{frames: down, rec: sessionReceipt(spec.JobID, 0, down, 101)},
				proto:       "realtime.v2",
			}, nil
		},
	}
	h := mustHub(t, Config{
		TEE:   fake,
		Rates: ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
	})
	link := &protocolLink{proto: "realtime.v1"}

	_, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, link)
	if !errors.Is(err, ErrSessionProtocolMismatch) {
		t.Fatalf("err = %v, want ErrSessionProtocolMismatch", err)
	}
	if link.down.Len() != 0 {
		t.Fatalf("downlink = %q, want nothing relayed before the handshake check", link.down.String())
	}
}

// TestRunRealtimeAcceptsMatchingSubprotocol is the positive control: the same
// protocol on both ends relays and settles normally.
func TestRunRealtimeAcceptsMatchingSubprotocol(t *testing.T) {
	down := [][]byte{[]byte("hello")}
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			return &handshakeTunnel{
				SessionConn: &scriptTunnel{frames: down, rec: sessionReceipt(spec.JobID, 0, down, 101)},
				proto:       "realtime.v1",
			}, nil
		},
	}
	h := mustHub(t, Config{
		TEE:   fake,
		Rates: ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 100}}),
	})
	link := &protocolLink{proto: "realtime.v1"}

	outcome, err := h.RunRealtime(context.Background(), "tenant", "m", buildSession, link)
	if err != nil {
		t.Fatalf("run realtime: %v", err)
	}
	if link.down.String() != "hello" {
		t.Fatalf("downlink = %q, want hello", link.down.String())
	}
	if !outcome.Stored {
		t.Fatal("a matching subprotocol session must settle")
	}
}

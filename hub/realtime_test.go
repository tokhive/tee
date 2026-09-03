package hub

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// These tests exercise the streaming-session engine — provider selection, byte
// relay, and settlement under the Hub's own bounds — against scripted tunnels,
// with no network and no real TEE. They cover what a request/response test
// cannot: a receipt whose bytes and hash must match what the relay actually
// moved, and a relay truncated by the Hub's byte cap that must still settle for
// the bytes it did move.
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
	var downBytes uint64
	for _, f := range down {
		downBytes += uint64(len(f))
	}
	r := proof.Receipt{
		Version:       proof.VersionV1,
		JobID:         jobID,
		Provider:      testProvider,
		StatusCode:    status,
		Completion:    proof.CompletionComplete,
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
// realtime entry would build.
func openSessionSpec(provider string) jobs.Spec {
	return jobs.Spec{
		Version:  jobs.VersionV1,
		JobID:    make([]byte, proof.JobIDLength),
		Provider: provider,
		Method:   "GET",
		Host:     "provider.test:443",
		Path:     "/v1/realtime",
		Stream:   true,
		Session:  true,
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

func TestRunRealtimeByteCapTruncatesButSettles(t *testing.T) {
	// Two frames; the cap lands between them, so only the first is relayed and
	// the session is truncated — but the receipt still covers every byte moved,
	// so the Hub can settle for what it actually delivered.
	down := [][]byte{[]byte("first"), []byte("second")}
	relayed := [][]byte{down[0]}
	fake := &ScriptedTEE{
		OpenReply: func(_ int, spec jobs.Spec) (SessionConn, error) {
			return &scriptTunnel{frames: down, rec: sessionReceipt(spec.JobID, 0, relayed, 101)}, nil
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
	// Truncated does not mean unsettled: the provider earned for real bytes.
	if !outcome.Stored {
		t.Fatalf("truncated session did not settle")
	}
	if outcome.Charged != 100 {
		t.Fatalf("charged = %d, want 100", outcome.Charged)
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
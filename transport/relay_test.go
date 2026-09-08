package transport

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tunnel"
)

// mustDialStream opens a stream on a client multiplexer and wraps it in the
// net.Conn adapter under test.
func mustDialStream(t *testing.T, m *tunnel.Multiplexer) *streamConn {
	t.Helper()
	s, err := m.Dial(nil)
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	return &streamConn{Stream: s}
}

// TestRelayStreamDeadlineInterruptsABlockedRead is the TEE-02 regression: a
// read parked on a silent upstream must be unblocked when the deadline fires —
// the HTTP exchange depends on deadlines to terminate a stalled request — and
// only that stream may be ended; its siblings on the same tunnel survive.
func TestRelayStreamDeadlineInterruptsABlockedRead(t *testing.T) {
	clientEnd, peerEnd := net.Pipe()
	defer clientEnd.Close()
	defer peerEnd.Close()
	mClient := tunnel.New(clientEnd, tunnel.High)
	mPeer := tunnel.New(peerEnd, tunnel.Low)
	mPeer.Serve(func(*tunnel.Stream, []byte) {}) // accept streams; never send on them

	blocked := mustDialStream(t, mClient)
	sibling := mustDialStream(t, mClient)

	readDone := make(chan error, 1)
	go func() {
		var buf [1]byte
		_, err := blocked.Read(buf[:])
		readDone <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the read park inside the tunnel
	if err := blocked.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("blocked read returned nil error after the deadline fired")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("deadline did not interrupt the read parked on the silent peer")
	}

	// The sibling stream must be untouched: writes still succeed and are framed
	// onto the tunnel (the peer multiplexer consumes them).
	if _, err := sibling.Write([]byte("ping")); err != nil {
		t.Errorf("sibling write failed after the other stream's deadline: %v", err)
	}
	// A write on the ended stream fails fast instead of hanging.
	if _, err := blocked.Write([]byte("x")); err == nil {
		t.Error("write on the deadline-ended stream returned nil error")
	}
}

// TestClearingADeadlineInvalidatesFiredCallbacks pins the generation bump on
// the clear path. The race it prevents: a deadline fires and its callback
// starts running — timer.Stop() then returns false, so a clear that runs
// before the callback's generation check must still invalidate it, or the
// callback closes a stream whose deadline was cleared. A relayed exchange
// finishing at the deadline boundary would otherwise hand back a connection
// that is dead on arrival.
//
// GOMAXPROCS(1) makes the interleaving deterministic: the fired callback can
// only run when this goroutine blocks, which is after the clear, so the
// callback always observes the cleared (bumped) generation.
func TestClearingADeadlineInvalidatesFiredCallbacks(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	c := &streamConn{}

	// Arm a deadline in the past: the timer fires immediately, and with one P
	// its callback cannot run ahead of the clear below.
	if err := c.setDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if c.gen != 1 {
		t.Fatalf("gen = %d after arming, want 1", c.gen)
	}

	// Clear the deadline. Must advance the generation: Stop() cannot cancel a
	// callback that has already fired, so the bump is the only thing between
	// the stale callback and a stream closed against an explicit clear.
	if err := c.setDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	if c.gen != 2 {
		t.Fatalf("gen = %d after clearing, want 2: a clear must invalidate a fired callback", c.gen)
	}

	// Let the stale callback run. With the generation bumped it sees a
	// mismatch and never touches the stream — a nil Stream here would panic on
	// a close, which is the failure mode the old code produced.
	time.Sleep(10 * time.Millisecond)
}

// TestRelayDialWithoutATunnelReturnsAnError is the TEE-03 regression: when the
// very first dial cannot even establish the tunnel (the relay endpoint is
// unreachable), Dial must return the dial error — not dereference a nil tunnel
// while trying to reset it.
func TestRelayDialWithoutATunnelReturnsAnError(t *testing.T) {
	// Reserve a port, then release it: nothing listens there any more, so a
	// dial to it is refused immediately and deterministically.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	r, err := NewRelay(RelayConfig{
		URL:            "ws://" + addr + "/v1/relay",
		ConnectTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	defer func() { _ = r.Close() }()

	conn, err := r.Dial(context.Background(), "provider", "upstream.host")
	if err == nil {
		t.Fatal("dial against an unreachable relay returned nil error")
	}
	if conn != nil {
		t.Errorf("dial returned a non-nil connection together with an error")
	}
}

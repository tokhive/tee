package tunnel

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// dialedPair builds two linked multiplexers over a net.Pipe: hub is the side
// that dials streams, cli is the side that serves them (it must bridge the
// inbound stream to whatever the test wants echoed back).
type dialedPair struct {
	hub *Multiplexer
	cli *Multiplexer
}

func newPair(t *testing.T, handle func(*Stream, []byte)) *dialedPair {
	t.Helper()
	a, b := net.Pipe()
	cli := New(a, High)
	hub := New(b, Low)
	if handle != nil {
		cli.Serve(handle)
	}
	t.Cleanup(func() { _ = hub.Close(); _ = cli.Close(); _ = a.Close(); _ = b.Close() })
	return &dialedPair{hub: hub, cli: cli}
}

// echo returns a handler that reads the whole stream and writes it back byte
// for byte, then closes — the simplest bridge a relay does.
func echo() func(*Stream, []byte) {
	return func(s *Stream, open []byte) {
		buf := make([]byte, 64*1024)
		for {
			n, err := s.Read(buf)
			if n > 0 {
				if _, werr := s.Write(buf[:n]); werr != nil {
					_ = s.Close()
					return
				}
			}
			if err != nil {
				_ = s.Close()
				return
			}
		}
	}
}

// TestRoundTrip drives one stream: hub writes data, cli echoes it back, hub
// reads the echo. It also checks the open metadata reaches the handler.
func TestRoundTrip(t *testing.T) {
	var gotOpen string
	pr := newPair(t, func(s *Stream, open []byte) {
		gotOpen = string(open)
		echo()(s, open)
	})

	stream, err := pr.hub.Dial([]byte("hello-open"))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	written := []byte("the quick brown fox jumps over the lazy dog")
	done := make(chan error, 1)
	go func() {
		_, werr := stream.Write(written)
		done <- werr
	}()

	back := make([]byte, len(written))
	if _, err := io.ReadFull(stream, back); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(back, written) {
		t.Fatalf("echo mismatch: %q", back)
	}
	if err := <-done; err != nil {
		t.Fatalf("write: %v", err)
	}
	if gotOpen != "hello-open" {
		t.Fatalf("open metadata = %q, want %q", gotOpen, "hello-open")
	}
}

// TestLargeWrite feeds a payload larger than one frame and verifies it arrives
// intact (the writer splits it, the reader reassembles it).
func TestLargeWrite(t *testing.T) {
	pr := newPair(t, echo())

	stream, err := pr.hub.Dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	payload := bytes.Repeat([]byte("0123456789abcdef"), maxPayload/16+100) // > maxPayload
	done := make(chan error, 1)
	go func() { _, err := stream.Write(payload); done <- err }()

	back := make([]byte, 0, len(payload))
	buf := make([]byte, 32*1024)
	for len(back) < len(payload) {
		n, rerr := stream.Read(buf)
		if n > 0 {
			back = append(back, buf[:n]...)
		}
		if rerr != nil {
			t.Fatalf("read: %v (got %d/%d)", rerr, len(back), len(payload))
		}
	}
	if !bytes.Equal(back, payload) {
		t.Fatalf("large payload corrupted: got %d bytes want %d", len(back), len(payload))
	}
	if err := <-done; err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestManyConcurrentStreams opens several streams at once and round-trips each
// to prove the flow-id demultiplexing keeps them isolated.
func TestManyConcurrentStreams(t *testing.T) {
	pr := newPair(t, echo())

	const n = 32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := pr.hub.Dial(nil)
			if err != nil {
				t.Errorf("dial %d: %v", i, err)
				return
			}
			defer s.Close()
			msg := fmt.Sprintf("message-%d", i)
			if _, err := s.Write([]byte(msg)); err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
			back := make([]byte, len(msg))
			if _, err := io.ReadFull(s, back); err != nil {
				t.Errorf("read %d: %v", i, err)
				return
			}
			if string(back) != msg {
				t.Errorf("stream %d crossed wires: %q", i, back)
			}
		}(i)
	}
	wg.Wait()
}

// TestClosePropagation confirms that when the serving side closes a stream, the
// dialing side's Read drains queued bytes then returns io.EOF.
func TestClosePropagation(t *testing.T) {
	pr := newPair(t, func(s *Stream, _ []byte) {
		_, _ = s.Write([]byte("bye"))
		_ = s.Close()
	})

	s, err := pr.hub.Dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("bye"))
	if _, err := io.ReadFull(s, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "bye" {
		t.Fatalf("read = %q, want %q", buf, "bye")
	}
	if _, err := s.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("after drain: err = %v, want EOF", err)
	}
}

// TestOversizedFrameRejected feeds a frame declaring a length above maxPayload
// at the raw byte level and confirms the receiver tears the tunnel down instead
// of allocating a huge buffer (the length is peer-controlled, unvalidated
// upstream).
func TestOversizedFrameRejected(t *testing.T) {
	a, b := net.Pipe()
	cli := New(a, High)
	cli.Serve(echo())

	var head [headerLen]byte
	frameHeader(head[:], KindData, 7, maxPayload+1)
	if _, err := b.Write(head[:]); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()

	// After the malformed frame, the multiplexer must be down: a subsequent Dial
	// fails instead of the tunnel quietly allocating a multi-MB buffer.
	done := make(chan error, 1)
	go func() {
		_, err := cli.Dial(nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected dial to fail after an oversized frame tore the tunnel down")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tunnel did not reject an oversized frame")
	}
}

func TestTunnelShutdownEndsStreams(t *testing.T) {
	a, b := net.Pipe()
	cli := New(a, High)
	cli.Serve(echo())
	hub := New(b, Low)

	s, err := hub.Dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = cli.Close()
	_ = a.Close()
	_ = b.Close()

	// Either EOF or an environment error is acceptable; it must not hang.
	buf := make([]byte, 32)
	rdone := make(chan error, 1)
	go func() { _, err := s.Read(buf); rdone <- err }()
	select {
	case <-rdone:
		// broke out; fine
	case <-time.After(2 * time.Second):
		t.Fatal("stream read hung after tunnel shutdown")
	}
}

// TestSlowStreamIsResetWithoutStallingOthers guards the multiplexer against one
// stream's backpressure freezing the shared read loop. A stream whose consumer
// never drains must be reset — its peer told, its reader ended — while a
// sibling stream on the same tunnel keeps carrying bytes.
//
// The read path is driven inline, exactly as the read loop drives it, so the
// ordering is deterministic: before the fix, deliver blocked forever once the
// slow stream's buffer passed maxBuf, so the sibling's bytes never arrived and
// this test timed out.
func TestSlowStreamIsResetWithoutStallingOthers(t *testing.T) {
	a, b := net.Pipe()
	m := New(a, High)
	defer func() { _ = m.Close(); _ = a.Close(); _ = b.Close() }()
	// Drain the mux's outbound so a reset's close frame never parks on net.Pipe.
	go func() { _, _ = io.Copy(io.Discard, b) }()

	slowCh := make(chan *Stream, 1)
	sibCh := make(chan *Stream, 1)
	m.Serve(func(s *Stream, open []byte) {
		if string(open) == "slow" {
			slowCh <- s
			return // no consumer: this stream is never read
		}
		sibCh <- s
	})

	m.acceptOpen(1, []byte("slow"))
	m.acceptOpen(2, nil)
	slow := <-slowCh
	sib := <-sibCh

	// Cross the per-stream buffer cap, then deliver to a sibling from the same
	// (single) read path. If push blocked, this goroutine never finishes.
	done := make(chan struct{})
	go func() {
		chunk := bytes.Repeat([]byte("x"), maxPayload)
		for i := 0; i < maxBuf/maxPayload+2; i++ {
			m.deliver(1, chunk)
		}
		m.deliver(2, []byte("pong"))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deliver blocked on a slow stream: the shared read loop would stall")
	}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(sib, buf); err != nil {
		t.Fatalf("sibling read while a stream was stuck: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("sibling read = %q, want %q", buf, "pong")
	}

	// The overrun stream was reset, not left half-open: draining it ends in EOF.
	if n, err := io.Copy(io.Discard, slow); err != nil {
		t.Fatalf("draining reset stream: %v", err)
	} else if n == 0 {
		t.Fatalf("reset stream buffered nothing; overflow path not exercised")
	}
}

// TestStreamBoundRefusesExtraStreams pins the tunnel's stream cap: a peer that
// opens more streams than the bound must be refused rather than admitted. Each
// stream costs a goroutine and up to maxBuf of buffer, so without the bound one
// runaway or hostile endpoint could exhaust the process's memory and scheduler.
func TestStreamBoundRefusesExtraStreams(t *testing.T) {
	a, b := net.Pipe()
	// The serving side admits exactly one stream, so the second dial must be
	// refused by the bound rather than by anything else.
	cli := NewLimited(a, High, 1)
	hub := New(b, Low)
	hold := make(chan struct{})
	defer func() {
		close(hold)
		_ = hub.Close()
		_ = cli.Close()
	}()
	admitted := make(chan struct{}, 1)
	cli.Serve(func(s *Stream, _ []byte) {
		admitted <- struct{}{}
		<-hold // occupy the only slot for the whole test
	})

	first, err := hub.Dial(nil)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	defer first.Close()
	select {
	case <-admitted:
	case <-time.After(2 * time.Second):
		t.Fatal("the first stream was never admitted")
	}

	second, err := hub.Dial(nil)
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	defer second.Close()

	// A refused open is answered with a close frame, so the dialer's stream
	// ends in EOF instead of being silently admitted.
	closed := make(chan struct{})
	go func() {
		buf := make([]byte, 8)
		if _, rerr := second.Read(buf); rerr == io.EOF {
			close(closed)
		}
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the over-bound stream was admitted instead of refused")
	}
}

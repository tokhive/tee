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

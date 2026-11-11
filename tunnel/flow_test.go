package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestWriterWaitsForCreditInsteadOfOverrunning is the reason the window exists:
// a transfer several times the receive buffer, into a consumer that is not
// reading yet, must wait for it rather than overrun the buffer and be reset.
// Before flow control this exact transfer ended in ErrStreamReset.
func TestWriterWaitsForCreditInsteadOfOverrunning(t *testing.T) {
	served := make(chan *Stream, 1)
	pr := newPair(t, func(s *Stream, _ []byte) { served <- s })

	s, err := pr.hub.Dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	inner := <-served

	payload := bytes.Repeat([]byte("0123456789abcdef"), 3*maxBuf/16)
	wrote := make(chan error, 1)
	go func() { _, werr := s.Write(payload); wrote <- werr }()

	// Nobody is reading: the writer must be parked on credit, not finished and
	// not failed, with no more than one window sitting in the peer's buffer.
	select {
	case werr := <-wrote:
		t.Fatalf("write returned (%v) while the peer had consumed nothing", werr)
	case <-time.After(200 * time.Millisecond):
	}
	inner.mu.Lock()
	buffered, ended := inner.buffered, inner.eof
	inner.mu.Unlock()
	if ended {
		t.Fatal("the stream ended while its writer should have been waiting")
	}
	if buffered > initialWindow {
		t.Fatalf("peer buffered %d bytes, more than the %d window", buffered, initialWindow)
	}

	// Once the consumer drains, the whole transfer arrives intact.
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(inner, got); err != nil {
		t.Fatalf("draining: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload corrupted across the window")
	}
	select {
	case werr := <-wrote:
		if werr != nil {
			t.Fatalf("write: %v", werr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer never resumed after the peer drained")
	}
}

// TestCloseWakesAWriterParkedOnCredit pins the only way out of a blocked write:
// the stream ending. A deadline on a relayed connection is enforced by closing
// the stream, so a writer that ignored the close would outlive its exchange.
func TestCloseWakesAWriterParkedOnCredit(t *testing.T) {
	served := make(chan *Stream, 1)
	pr := newPair(t, func(s *Stream, _ []byte) { served <- s })

	s, err := pr.hub.Dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	<-served

	wrote := make(chan error, 1)
	go func() { _, werr := s.Write(make([]byte, 2*initialWindow)); wrote <- werr }()
	select {
	case werr := <-wrote:
		t.Fatalf("write returned (%v) before the window was exhausted", werr)
	case <-time.After(100 * time.Millisecond):
	}
	_ = s.Close()
	select {
	case werr := <-wrote:
		if !errors.Is(werr, io.ErrClosedPipe) {
			t.Fatalf("write after close = %v, want io.ErrClosedPipe", werr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close did not wake the blocked writer")
	}
}

// TestPeerWithoutHelloIsNotThrottled covers a peer built before flow control:
// it never says hello and never grants credit, so a writer that waited for it
// would wait forever. Streams to it must run unthrottled, as they always did.
func TestPeerWithoutHelloIsNotThrottled(t *testing.T) {
	a, b := net.Pipe()
	m := New(a, High)
	defer func() { _ = m.Close(); _ = a.Close(); _ = b.Close() }()
	// The old peer: reads everything, says nothing.
	go func() { _, _ = io.Copy(io.Discard, b) }()

	s, err := m.Dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	wrote := make(chan error, 1)
	go func() { _, werr := s.Write(make([]byte, 3*initialWindow)); wrote <- werr }()
	select {
	case werr := <-wrote:
		if werr != nil {
			t.Fatalf("write: %v", werr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer waited for credit a pre-flow-control peer will never grant")
	}
}

// TestFrameIsOneWrite pins the framing economy: the carrier turns every Write
// into one message, so a frame written as header-then-payload costs two.
func TestFrameIsOneWrite(t *testing.T) {
	var w countingWriter
	var scratch []byte
	if err := writeFrames(&w, &scratch, KindData, 7, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if w.writes != 1 {
		t.Fatalf("one frame took %d writes, want 1", w.writes)
	}
	if w.buf.Len() != headerLen+5 {
		t.Fatalf("frame is %d bytes, want %d", w.buf.Len(), headerLen+5)
	}
}

type countingWriter struct {
	buf    bytes.Buffer
	writes int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes++
	return c.buf.Write(p)
}

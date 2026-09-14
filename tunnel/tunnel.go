// Package tunnel multiplexes many bidirectional byte streams over a single
// underlying connection. It is what lets a Provider Agent behind a home NAT
// keep exactly one long-lived connection open to the Hub while many distinct
// TEE-to-provider connections flow through it at once.
//
// Why a custom multiplexer instead of raw WebSocket messages: each TEE
// connection (a request channel or a streaming session) must be an independent
// byte pipe with reliable per-stream close and backpressure. A shared channel
// cannot give each pipe those properties without a framing layer on top — which
// is exactly what this package provides. It is payload-agnostic: it carries
// bytes and close signals, never their meaning.
//
// The framing is a 13-byte header (kind, 8-byte flow id, 4-byte length) over an
// io.ReadWriter, so it runs on any full-duplex stream — a WebSocket binary pipe
// in production, a net.Pipe in tests. A single reader goroutine demultiplexes
// inbound frames onto their streams; outbound frames are serialized under one
// lock. Flow ids are collision-free across the two endpoints because one side
// mints ids in the upper half of the space and the other in the lower half.
package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Kind identifies what a frame carries.
type Kind uint8

const (
	// KindOpen opens a new stream. The payload is opaque open metadata supplied
	// by the dialing side; the receiving endpoint hands it, with a new Stream,
	// to its open handler.
	KindOpen Kind = 1
	// KindData carries stream payload bytes.
	KindData Kind = 2
	// KindClose ends a stream. The payload is an informational reason: empty
	// for a close, closeReasonReset for a reset (see ErrStreamReset).
	KindClose Kind = 3
)

// Frame boundaries. The header is kind + 8-byte flow id + 4-byte length.
const (
	headerLen  = 13
	maxPayload = 1 << 20 // one stream write can span several frames, so no single frame needs more
	maxBuf     = 8 << 20 // inbound buffering cap per stream; further data resets that stream
)

// DefaultMaxStreams bounds how many streams one tunnel carries at once.
// Per-stream inbound buffering is already capped (maxBuf), but the *number* of
// streams is not, so without a bound a peer could mint streams until the
// process exhausted memory or goroutines — each stream costs a goroutine and
// up to maxBuf of buffer. A Hub relays one stream per in-flight request, so
// this is generous for real load and only bites a runaway or hostile peer.
const DefaultMaxStreams = 1024

var (
	// ErrClosed means the multiplexer itself has shut down: every stream is
	// broken and no new one can be opened.
	ErrClosed = errors.New("tunnel: multiplexer closed")

	// ErrTunnelFailed means the tunnel itself went down — the carrier's read or
	// write failed, or a peer sent a frame the framing cannot accept — so every
	// stream on it was cut mid-transfer. A consumer that took io.EOF for that
	// would report a whole transfer, which for a session (whose stream carries no
	// framing of its own) is the only evidence of a cut there is. A stream the
	// peer closed, and a stream ended by a deliberate Close, still end in io.EOF.
	ErrTunnelFailed = errors.New("tunnel: carrier or framing failure")

	// ErrStreamReset means a stream was reset rather than closed: one side's
	// consumer fell so far behind that its buffer crossed maxBuf, so the stream
	// was torn down instead of stalling the shared read loop (see push). Both
	// ends report it — the side that was behind, and the side whose bytes were
	// being dropped — because a reset is a truncated transfer, and a reader
	// told io.EOF instead would pass it on as a whole one. A stream a peer
	// closed deliberately still ends in io.EOF.
	ErrStreamReset = errors.New("tunnel: stream reset (transfer truncated)")
)

// closeReasonReset is the KindClose payload that marks a stream reset. An empty
// payload is a plain close; anything else is the reason, currently only this.
var closeReasonReset = []byte("reset")

func frameHeader(buf []byte, kind Kind, id uint64, n uint32) {
	buf[0] = byte(kind)
	binary.BigEndian.PutUint64(buf[1:9], id)
	binary.BigEndian.PutUint32(buf[9:13], n)
}

// Endpoint is the local side, used to keep flow ids collision-free: one side
// allocates ids below the high bit, the other at or above it.
type Endpoint int

const (
	// Low allocates ids in [0, 2^63).
	Low Endpoint = 0
	// High allocates ids in [2^63, 2^64).
	High Endpoint = 1
)

// Connection is the minimal full-duplex surface the multiplexer needs.
type Connection interface {
	io.Reader
	io.Writer
}

// Multiplexer runs a framed, multiplexed tunnel over conn.
type Multiplexer struct {
	conn Connection
	// writeMu serializes outbound frames so concurrent stream writes never
	// interleave a single frame.
	writeMu sync.Mutex
	// mu guards streams and nextID; closed is read-only trends.
	mu      sync.Mutex
	streams map[uint64]*Stream
	closed  bool
	nextID  uint64
	idBit   uint64

	// maxStreams bounds len(streams); zero means unlimited.
	maxStreams int

	// openHandler is invoked for each stream the peer opens. Set with Serve.
	openHandler func(*Stream, []byte)
}

// New returns a multiplexer over conn with the default stream bound; a single
// goroutine reads and demultiplexes inbound frames.
func New(conn Connection, side Endpoint) *Multiplexer {
	return NewLimited(conn, side, DefaultMaxStreams)
}

// NewLimited is New with an explicit cap on concurrent streams. A
// non-positive maxStreams means unlimited, which is only appropriate for a
// tunnel whose peer is fully trusted.
func NewLimited(conn Connection, side Endpoint, maxStreams int) *Multiplexer {
	m := &Multiplexer{
		conn:       conn,
		streams:    make(map[uint64]*Stream),
		idBit:      uint64(side) << 63,
		maxStreams: maxStreams,
	}
	go m.readLoop()
	return m
}

// Serve installs the handler for streams the peer opens. A nil handler (or none)
// closes an inbound stream at once, so an unexpected open cannot pin a stream.
// Serve may be called until the first bytes are read.
func (m *Multiplexer) Serve(handle func(*Stream, []byte)) {
	m.mu.Lock()
	m.openHandler = handle
	m.mu.Unlock()
}

// Dial opens a new stream to the peer, carrying opaque open metadata. It
// returns immediately; the peer may close it before or after any data flows,
// which the stream's Read surfaces as io.EOF.
func (m *Multiplexer) Dial(open []byte) (*Stream, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrClosed
	}
	id := m.nextID | m.idBit
	m.nextID++
	s := newStream(m, id)
	m.streams[id] = s
	m.mu.Unlock()

	if err := m.writeFrame(KindOpen, id, open); err != nil {
		m.drop(s)
		return nil, err
	}
	return s, nil
}

// Close shuts the multiplexer down, ending every stream cleanly: a deliberate
// shutdown is not a broken transfer, so its streams report io.EOF.
func (m *Multiplexer) Close() error {
	m.teardown(nil)
	return nil
}

// writeFrame gains the write lock and writes one frame, refusing a closed tunnel.
func (m *Multiplexer) writeFrame(kind Kind, id uint64, payload []byte) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if err := writeFrames(m.conn, kind, id, payload); err != nil {
		m.fail(err)
		return err
	}
	return nil
}

// writeFrames splits payload into maxPayload-sized frames and writes them all.
func writeFrames(w io.Writer, kind Kind, id uint64, payload []byte) error {
	var head [headerLen]byte
	if len(payload) == 0 {
		frameHeader(head[:], kind, id, 0)
		_, err := w.Write(head[:])
		return err
	}
	for len(payload) > 0 {
		n := len(payload)
		if n > maxPayload {
			n = maxPayload
		}
		frameHeader(head[:], kind, id, uint32(n))
		if _, err := w.Write(head[:]); err != nil {
			return err
		}
		if _, err := w.Write(payload[:n]); err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

// readLoop reads frames until the connection fails, dispensing each onto the
// right stream (or handling it directly for open/close).
func (m *Multiplexer) readLoop() {
	var head [headerLen]byte
	for {
		if _, err := io.ReadFull(m.conn, head[:]); err != nil {
			m.fail(err)
			return
		}
		kind := Kind(head[0])
		id := binary.BigEndian.Uint64(head[1:9])
		n := binary.BigEndian.Uint32(head[9:13])
		// The length is peer-controlled wire input and must be bounded before it
		// is used to allocate: a malformed or hostile peer could otherwise declare
		// a huge frame and exhaust memory. Legitimate writers never exceed
		// maxPayload per frame.
		if n > maxPayload {
			m.fail(fmt.Errorf("tunnel: oversized frame length %d", n))
			return
		}
		payload := make([]byte, n)
		if n > 0 {
			if _, err := io.ReadFull(m.conn, payload); err != nil {
				m.fail(err)
				return
			}
		}

		switch kind {
		case KindOpen:
			m.acceptOpen(id, payload)
		case KindData:
			m.deliver(id, payload)
		case KindClose:
			m.receiveClose(id, payload)
		default:
			// Unknown kinds are ignored for forward compatibility.
		}
	}
}

func (m *Multiplexer) acceptOpen(id uint64, payload []byte) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	if m.streams[id] != nil { // duplicate id: misbehaving peer, drop it
		m.mu.Unlock()
		return
	}
	if m.maxStreams > 0 && len(m.streams) >= m.maxStreams {
		// The tunnel is already at its stream bound. Refuse the open rather
		// than admit another goroutine and buffer: the peer is told with a
		// close frame, off the read loop because writing can block on a
		// stalled carrier. A refused stream costs one short-lived write and
		// nothing else.
		m.mu.Unlock()
		go func() { _ = m.writeFrame(KindClose, id, nil) }()
		return
	}
	s := newStream(m, id)
	m.streams[id] = s
	handler := m.openHandler
	m.mu.Unlock()

	if handler == nil {
		s.Close()
		return
	}
	// The handler bridges the stream (e.g. io.Copy to an external socket) and so
	// may block for the whole life of the stream. Running it on the single
	// readLoop goroutine would stall every other stream on this tunnel, so each
	// opened stream gets its own goroutine.
	go handler(s, payload)
}

func (m *Multiplexer) deliver(id uint64, payload []byte) {
	m.mu.Lock()
	s := m.streams[id]
	m.mu.Unlock()
	if s != nil {
		s.push(payload)
	}
}

// receiveClose ends a stream the peer ended. The reason decides what this
// side's reader is told once its queue drains: a reset is carried across the
// wire rather than left behind, because the peer may be the one that dropped
// bytes this side is still waiting for.
func (m *Multiplexer) receiveClose(id uint64, reason []byte) {
	m.mu.Lock()
	s := m.streams[id]
	delete(m.streams, id)
	m.mu.Unlock()
	if s == nil {
		return
	}
	if string(reason) == string(closeReasonReset) {
		s.end(ErrStreamReset)
		return
	}
	s.eofNow()
}

// drop removes a stream from the registry and breaks it (used on local close or
// dial failure).
func (m *Multiplexer) drop(s *Stream) {
	m.mu.Lock()
	delete(m.streams, s.id)
	m.mu.Unlock()
	s.eofNow()
}

// Resetter is implemented by a connection that can end abnormally rather than
// merely close, so its peer is told the transfer was cut. Stream implements it;
// a plain socket cannot, which is why Bridge falls back to closing.
type Resetter interface{ Reset() error }

// Reset ends rw abnormally when it can say so, and closes it otherwise: a plain
// socket has no way to report a truncation, so a close is all it can express.
func Reset(rw io.Closer) error {
	if r, ok := rw.(Resetter); ok {
		return r.Reset()
	}
	return rw.Close()
}

// Bridge copies bytes in both directions between two read-write-closers until
// either side closes, then ends both. Ending both is what unblocks the other
// goroutine: a half-open bridge would otherwise pin a pair of connections
// forever. It is shared by the Hub's agent relay and the Provider Agent's
// upstream bridge, which both do the same ciphertext-only copy.
//
// How the pair ends is decided by whichever copy finishes first, and only by
// that one: the loser returns an error the first close caused, which says
// nothing about the transfer. A copy that ended with an error did not reach the
// end of the stream — the carrier failed, the peer vanished, a buffer
// overflowed — so both ends are ended abnormally. Passing that on as a plain
// close would tell the far side a truncated transfer was a whole one, and that
// side may be the one signing the receipt.
func Bridge(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	var decide sync.Once
	copyOne := func(dst, src io.ReadWriteCloser) {
		_, err := io.Copy(dst, src)
		decide.Do(func() { endBoth(a, b, err) })
		done <- struct{}{}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
}

// endBoth ends both ends of a bridge the way the copy that finished first said
// the transfer ended. io.Copy reports a clean end of stream as a nil error and
// everything else as the failure it was, and the two are ended differently for
// that reason: a peer that is told "closed" will report a whole transfer.
func endBoth(a, b io.ReadWriteCloser, err error) {
	if err == nil {
		_ = a.Close()
		_ = b.Close()
		return
	}
	_ = Reset(a)
	_ = Reset(b)
}

// fail tears the whole tunnel down after a read/write error on the carrier.
// Every stream on it ends with ErrTunnelFailed wrapping the cause, rather than a
// clean EOF: the bytes they were carrying are cut, and a consumer told io.EOF
// would take what it got for the whole of it. For a session that is the only
// evidence the stream can give, so a flattened failure is what lets a cut
// conversation be settled as a finished one.
func (m *Multiplexer) fail(cause error) {
	m.teardown(fmt.Errorf("%w: %v", ErrTunnelFailed, cause))
}

// teardown marks the tunnel shut and ends every stream with reason: a carrier
// fault, or nothing for a deliberate Close. It is idempotent, so the reader and
// any number of writers can race into it and the first reason stands.
func (m *Multiplexer) teardown(reason error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	streams := make([]*Stream, 0, len(m.streams))
	for _, s := range m.streams {
		streams = append(streams, s)
	}
	m.streams = make(map[uint64]*Stream)
	m.mu.Unlock()
	for _, s := range streams {
		s.end(reason)
	}
}

// Stream is one bidirectional byte pipe carried by a Multiplexer. Read and
// Write are safe for concurrent use.
type Stream struct {
	id uint64
	m  *Multiplexer

	mu   sync.Mutex
	cond *sync.Cond
	buf  []byte
	eof  bool
	// err is what a reader sees once the queued bytes are drained, in place of
	// io.EOF: nil for a clean end, ErrStreamReset for a stream that was reset.
	err error
}

func newStream(m *Multiplexer, id uint64) *Stream {
	s := &Stream{id: id, m: m}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Read delivers the next inbound bytes. Once the queued bytes are drained it
// returns io.EOF for a clean end — the peer closed the stream, or the tunnel was
// shut down deliberately — and otherwise the reason the transfer was cut:
// ErrStreamReset for a stream reset (see push), ErrTunnelFailed for a tunnel
// that went down. A consumer must not treat those as ends: reporting a truncated
// transfer as whole is what a receipt may never do.
func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.buf) == 0 && !s.eof {
		s.cond.Wait()
	}
	if len(s.buf) > 0 {
		n := copy(p, s.buf)
		s.buf = s.buf[n:]
		s.cond.Signal() // room for a blocked push
		return n, nil
	}
	if s.err != nil {
		return 0, s.err
	}
	return 0, io.EOF
}

// Write sends payload to the peer, splitting it across frames as needed. It
// returns an error once the stream (or the tunnel) has ended.
func (s *Stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	eof, ended := s.eof, s.err
	s.mu.Unlock()
	if eof {
		// Report why the stream ended when there is a reason: a reset is a
		// different fact from a peer that closed, and the writer is the side
		// whose bytes were being dropped.
		if ended != nil {
			return 0, ended
		}
		return 0, io.ErrClosedPipe
	}
	if err := s.m.writeFrame(KindData, s.id, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close ends the stream: the local reader returns io.EOF, the peer receives a
// close frame, and the stream is dropped from the tunnel. A stream that was
// already reset keeps that verdict — its frame carries the reset reason —
// because the close is whatever this stream's end turned out to be, and a
// truncated transfer is not the same fact as a whole one. That is what makes a
// caller's own Close, racing the reset that a bridge or an overrun raised, still
// tell the peer the truth.
func (s *Stream) Close() error {
	_ = s.m.writeFrame(KindClose, s.id, s.closeFrame())
	s.m.drop(s)
	return nil
}

// Reset ends the stream abnormally: this side's reader is told ErrStreamReset
// and the peer receives a close frame carrying the reset reason, so neither end
// can take the cut transfer for a whole one. It is what a bridge calls when the
// direction it was copying failed, and what push calls — off the read loop —
// when a consumer falls so far behind that its bytes are dropped.
func (s *Stream) Reset() error {
	s.end(ErrStreamReset)
	_ = s.m.writeFrame(KindClose, s.id, closeReasonReset)
	s.m.drop(s)
	return nil
}

// closeFrame is the KindClose payload this stream's end warrants: the reset
// reason once it has been reset, nothing for a deliberate close.
func (s *Stream) closeFrame() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if errors.Is(s.err, ErrStreamReset) {
		return closeReasonReset
	}
	return nil
}

// push queues inbound bytes. It never blocks its caller, which is the single
// read loop: a stream whose consumer is not draining is reset rather than
// waiting, so one stuck stream cannot freeze every other stream — and then the
// carrier itself, once TCP backpressure reaches the peer. The reset ends just
// this stream: its reader drains what was buffered and then sees
// ErrStreamReset, and the peer is told with a close frame carrying the same
// reason. No-op after the stream has ended.
func (s *Stream) push(data []byte) {
	s.mu.Lock()
	if s.eof {
		s.mu.Unlock()
		return
	}
	if len(s.buf)+len(data) > maxBuf {
		// The consumer is not draining. Unblock this stream's reader and tell
		// the peer, both off the read loop: the reader with a reset error rather
		// than EOF, the peer with the reason in the close frame. Those bytes are
		// dropped, so what left the tunnel is a prefix — an end of transfer that
		// looks like a clean one is what lets a receiver attest, and bill, a
		// transcript that never arrived. The frame goes out on its own goroutine
		// because writing it can itself block on a stalled carrier — and would
		// then hold the shared write lock — which must not happen on the read
		// loop. Exactly one such goroutine is minted per stream: the eof flag set
		// below makes every later push return early.
		s.eof = true
		s.err = ErrStreamReset
		s.cond.Broadcast()
		s.mu.Unlock()
		go s.Reset()
		return
	}
	s.buf = append(s.buf, data...)
	s.cond.Signal()
	s.mu.Unlock()
}

// eofNow breaks the stream unconditionally and never reopens it. A reason
// already recorded — a reset — stands: the condition that ended the stream does
// not become less true because something later closed it.
func (s *Stream) eofNow() { s.end(nil) }

// end finishes the stream and records why. A nil reason is the clean end a
// peer's close or a deliberate shutdown produces; a non-nil one is reported by
// Read once the queued bytes are drained.
func (s *Stream) end(reason error) {
	s.mu.Lock()
	s.eof = true
	if s.err == nil {
		s.err = reason
	}
	s.cond.Broadcast()
	s.mu.Unlock()
}

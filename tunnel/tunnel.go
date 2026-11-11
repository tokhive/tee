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
//
// # Backpressure
//
// Each stream is flow-controlled by a credit window. A writer may have at most
// initialWindow bytes outstanding — sent but not yet consumed by the peer's
// reader — and blocks beyond that until the peer grants more with a KindWindow
// frame, which it does as its consumer drains. That is what lets a transfer
// larger than the receive buffer cross a hop whose far side is slower than its
// near side: the writer waits instead of overrunning the buffer and having the
// stream reset under it.
//
// The window is only enforced against a peer that announced it understands it
// (KindHello, the first frame either side writes). A peer that never says so is
// an older build that grants no credit, and waiting on it would wait forever, so
// streams to it run unthrottled exactly as they did before — with the receive
// buffer cap (maxBuf) still resetting a stream whose consumer falls behind.
package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
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
	// KindWindow grants the peer credit to send more bytes on a stream. The
	// payload is a 4-byte big-endian count of bytes the local reader consumed
	// since the last grant.
	KindWindow Kind = 4
	// KindHello announces that this endpoint grants credit, and is the first
	// frame it ever writes. It carries no payload and names no stream. An
	// endpoint enforces the send window only once it has seen its peer's hello;
	// builds that predate flow control ignore both kinds as unknown.
	KindHello Kind = 5
)

// Frame boundaries. The header is kind + 8-byte flow id + 4-byte length.
const (
	headerLen  = 13
	maxPayload = 1 << 20 // one stream write can span several frames, so no single frame needs more
	maxBuf     = 8 << 20 // inbound buffering cap per stream; further data resets that stream

	// initialWindow is how many bytes a writer may have outstanding on one
	// stream before it must wait for credit. It sits below maxBuf so a peer that
	// honours the window can never trip the reset that guards against one that
	// does not.
	initialWindow = 4 << 20
	// windowUpdateThreshold is how much a reader consumes before it tells the
	// peer. Granting in quarters keeps the control traffic negligible while
	// never leaving a writer parked on credit the reader has already freed: a
	// writer blocks only with a full window outstanding, and at most one
	// threshold of that can be consumed-but-ungranted.
	windowUpdateThreshold = initialWindow / 4

	// maxKeptScratch bounds the write scratch buffer a multiplexer keeps between
	// frames. Small frames — the common case for a token stream — reuse it; a
	// full-size frame borrows a larger one and gives it back, so an idle tunnel
	// does not sit on a megabyte it used once.
	maxKeptScratch = 64 << 10
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
	// interleave a single frame. It also guards helloSent and scratch.
	writeMu   sync.Mutex
	helloSent bool
	scratch   []byte
	// peerWindowed is set once the peer's hello has been read: from then on
	// stream writes are held to the credit window.
	peerWindowed atomic.Bool
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
	// Say hello promptly rather than with the first frame that happens to be
	// written, so a peer that only ever receives still learns it may be held to
	// the window. Off the caller's goroutine because the carrier can block.
	go m.hello()
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

// hello writes the KindHello frame if nothing has been written yet.
func (m *Multiplexer) hello() {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	_ = m.writeLocked(KindHello, 0, nil)
}

// writeFrame gains the write lock and writes one frame, refusing a closed tunnel.
func (m *Multiplexer) writeFrame(kind Kind, id uint64, payload []byte) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	return m.writeLocked(kind, id, payload)
}

// writeLocked writes one frame, preceded by this endpoint's hello if that has
// not gone out yet: the hello is always the first thing a peer reads, so by the
// time any of its streams carries data the peer already knows whether to wait
// for credit. Caller holds writeMu.
func (m *Multiplexer) writeLocked(kind Kind, id uint64, payload []byte) error {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if !m.helloSent {
		m.helloSent = true
		if err := writeFrames(m.conn, &m.scratch, KindHello, 0, nil); err != nil {
			m.fail(err)
			return err
		}
		if kind == KindHello {
			return nil
		}
	} else if kind == KindHello {
		return nil
	}
	err := writeFrames(m.conn, &m.scratch, kind, id, payload)
	if cap(m.scratch) > maxKeptScratch {
		m.scratch = nil
	}
	if err != nil {
		m.fail(err)
		return err
	}
	return nil
}

// writeFrames splits payload into maxPayload-sized frames and writes them all.
//
// Each frame goes out in a single Write, header and payload together. The
// carrier turns every Write into one message (see wsStream), so writing the two
// halves separately doubled the message count of a stream of small chunks —
// which is what a token stream is. scratch is the buffer the frame is assembled
// in, reused across calls.
func writeFrames(w io.Writer, scratch *[]byte, kind Kind, id uint64, payload []byte) error {
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
		frame := append((*scratch)[:0], head[:]...)
		frame = append(frame, payload[:n]...)
		*scratch = frame
		if _, err := w.Write(frame); err != nil {
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
		case KindWindow:
			m.receiveWindow(id, payload)
		case KindHello:
			m.peerWindowed.Store(true)
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

// receiveWindow credits a stream with the bytes its peer's reader consumed. A
// grant for a stream that has already ended, or one that is not four bytes, is
// dropped: there is nothing left to send on the one and no count in the other.
func (m *Multiplexer) receiveWindow(id uint64, payload []byte) {
	if len(payload) != 4 {
		return
	}
	m.mu.Lock()
	s := m.streams[id]
	m.mu.Unlock()
	if s != nil {
		s.grant(binary.BigEndian.Uint32(payload))
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
	// chunks is the inbound queue: the frames the read loop delivered, in
	// order, each owned by the stream from the moment it is pushed. head is how
	// much of chunks[0] a reader has already taken, and buffered is the total
	// still unread. Queuing the frames themselves, rather than appending them to
	// one growing buffer, is what keeps a delivered byte from being copied twice
	// on its way to the reader.
	chunks   [][]byte
	head     int
	buffered int
	eof      bool
	// err is what a reader sees once the queued bytes are drained, in place of
	// io.EOF: nil for a clean end, ErrStreamReset for a stream that was reset.
	err error

	// wcond wakes writers parked on credit. It shares mu with cond but is a
	// separate condition so that a Signal meant for a reader is never spent on
	// a writer, or the reverse.
	wcond *sync.Cond
	// credit is how many more bytes this side may send before it must wait for
	// a grant. It is counted from the first byte whether or not the window is
	// being enforced yet, so the two ends agree on it whenever enforcement
	// starts; it can therefore be negative.
	credit int64
	// consumed is what the local reader has taken since the last grant.
	consumed int
}

func newStream(m *Multiplexer, id uint64) *Stream {
	s := &Stream{id: id, m: m, credit: initialWindow}
	s.cond = sync.NewCond(&s.mu)
	s.wcond = sync.NewCond(&s.mu)
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
	for s.buffered == 0 && !s.eof {
		s.cond.Wait()
	}
	if s.buffered == 0 {
		err := s.err
		s.mu.Unlock()
		if err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	n := copy(p, s.chunks[0][s.head:])
	s.head += n
	s.buffered -= n
	if s.head == len(s.chunks[0]) {
		s.chunks[0] = nil
		s.chunks = s.chunks[1:]
		s.head = 0
		if len(s.chunks) == 0 {
			s.chunks = nil
		}
	}
	// Tell the peer what was freed, in batches. Nothing is owed to a stream
	// that has ended, or to a peer that does not count credit at all.
	var grant int
	if s.m.peerWindowed.Load() && !s.eof {
		s.consumed += n
		if s.consumed >= windowUpdateThreshold {
			grant, s.consumed = s.consumed, 0
		}
	}
	s.mu.Unlock()
	if grant > 0 {
		var credit [4]byte
		binary.BigEndian.PutUint32(credit[:], uint32(grant))
		_ = s.m.writeFrame(KindWindow, s.id, credit[:])
	}
	return n, nil
}

// grant adds credit the peer's reader freed and wakes any writer waiting on it.
func (s *Stream) grant(n uint32) {
	s.mu.Lock()
	s.credit += int64(n)
	s.wcond.Broadcast()
	s.mu.Unlock()
}

// Write sends payload to the peer, splitting it across frames as needed. It
// returns an error once the stream (or the tunnel) has ended.
//
// Against a peer that grants credit it blocks while a full window is
// outstanding, and resumes as the peer's reader drains. Nothing but the
// stream's own end wakes it early, which is the same rule Read follows: a
// caller that needs a bound closes the stream (see transport.streamConn, which
// turns a deadline into exactly that).
func (s *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		s.mu.Lock()
		windowed := s.m.peerWindowed.Load()
		for windowed && s.credit <= 0 && !s.eof {
			s.wcond.Wait()
		}
		if s.eof {
			// Report why the stream ended when there is a reason: a reset is a
			// different fact from a peer that closed, and the writer is the
			// side whose bytes were being dropped.
			ended := s.err
			s.mu.Unlock()
			if ended != nil {
				return total, ended
			}
			return total, io.ErrClosedPipe
		}
		n := min(len(p), maxPayload)
		if windowed && int64(n) > s.credit {
			n = int(s.credit)
		}
		s.credit -= int64(n)
		s.mu.Unlock()

		if err := s.m.writeFrame(KindData, s.id, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
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

// push queues inbound bytes, taking ownership of data. It never blocks its caller, which is the single
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
	if len(data) == 0 {
		s.mu.Unlock()
		return
	}
	if s.buffered+len(data) > maxBuf {
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
		s.wcond.Broadcast()
		s.mu.Unlock()
		go s.Reset()
		return
	}
	s.chunks = append(s.chunks, data)
	s.buffered += len(data)
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
	s.wcond.Broadcast()
	s.mu.Unlock()
}

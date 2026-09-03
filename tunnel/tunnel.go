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
	// KindClose ends a stream. The payload is an informational reason.
	KindClose Kind = 3
)

// Frame boundaries. The header is kind + 8-byte flow id + 4-byte length.
const (
	headerLen  = 13
	maxPayload = 1 << 20 // one stream write can span several frames, so no single frame needs more
	maxBuf     = 8 << 20 // inbound buffering cap per stream; further data stalls the sender
)

var (
	// ErrClosed means the multiplexer itself has shut down: every stream is
	// broken and no new one can be opened.
	ErrClosed = errors.New("tunnel: multiplexer closed")
)

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

	// openHandler is invoked for each stream the peer opens. Set with Serve.
	openHandler func(*Stream, []byte)
}

// New returns a multiplexer over conn; a single goroutine reads and
// demultiplexes inbound frames.
func New(conn Connection, side Endpoint) *Multiplexer {
	m := &Multiplexer{
		conn:    conn,
		streams: make(map[uint64]*Stream),
		idBit:   uint64(side) << 63,
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

// Close shuts the multiplexer down, ending every stream.
func (m *Multiplexer) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	streams := make([]*Stream, 0, len(m.streams))
	for _, s := range m.streams {
		streams = append(streams, s)
	}
	m.streams = make(map[uint64]*Stream)
	m.mu.Unlock()

	for _, s := range streams {
		s.eofNow()
	}
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
		m.mu.Lock()
		m.closed = true
		streams := make([]*Stream, 0, len(m.streams))
		for _, s := range m.streams {
			streams = append(streams, s)
		}
		m.streams = make(map[uint64]*Stream)
		m.mu.Unlock()
		for _, s := range streams {
			s.eofNow()
		}
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
			m.receiveClose(id)
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

func (m *Multiplexer) receiveClose(id uint64) {
	m.mu.Lock()
	s := m.streams[id]
	delete(m.streams, id)
	m.mu.Unlock()
	if s != nil {
		s.eofNow()
	}
}

// drop removes a stream from the registry and breaks it (used on local close or
// dial failure).
func (m *Multiplexer) drop(s *Stream) {
	m.mu.Lock()
	delete(m.streams, s.id)
	m.mu.Unlock()
	s.eofNow()
}

// Bridge copies bytes in both directions between two read-write-closers until
// either side closes. The first direction to finish closes both ends, which
// unblocks the other goroutine: a half-open bridge would otherwise pin a pair of
// connections forever. It is shared by the Hub's agent relay and the Provider
// Agent's upstream bridge, which both do the same ciphertext-only copy.
func Bridge(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
		_ = a.Close()
		_ = b.Close()
	}()
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
		_ = a.Close()
		_ = b.Close()
	}()
	<-done
}

// fail tears the whole tunnel down after a read/write error.
func (m *Multiplexer) fail(err error) {
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
		s.eofNow()
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
}

func newStream(m *Multiplexer, id uint64) *Stream {
	s := &Stream{id: id, m: m}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Read delivers the next inbound bytes. After the peer has closed (or the
// tunnel failed) and the queued bytes are drained, it returns io.EOF.
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
	return 0, io.EOF
}

// Write sends payload to the peer, splitting it across frames as needed. It
// returns an error once the stream (or the tunnel) has ended.
func (s *Stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	eof := s.eof
	s.mu.Unlock()
	if eof {
		return 0, io.ErrClosedPipe
	}
	if err := s.m.writeFrame(KindData, s.id, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close ends the stream: the local reader returns io.EOF, the peer receives a
// close frame, and the stream is dropped from the tunnel.
func (s *Stream) Close() error {
	_ = s.m.writeFrame(KindClose, s.id, nil)
	s.m.drop(s)
	return nil
}

// push queues inbound bytes, applying backpressure once the buffered backlog
// passes maxBuf. It no-ops after the stream has ended.
func (s *Stream) push(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.buf) >= maxBuf && !s.eof {
		s.cond.Wait()
	}
	if s.eof {
		return
	}
	s.buf = append(s.buf, data...)
	s.cond.Signal()
}

// eofNow breaks the stream unconditionally and never reopens it.
func (s *Stream) eofNow() {
	s.mu.Lock()
	s.eof = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

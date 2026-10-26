package hub

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// WebSocket frame opcodes. The Hub is the only component that interprets a
// frame: the TEE relays bytes, so both the user and the provider speak
// WebSocket through this file.
const (
	WSOpContinuation = 0x0
	WSOpText         = 0x1
	WSOpBinary       = 0x2
	WSOpClose        = 0x8
	WSOpPing         = 0x9
	WSOpPong         = 0xA
)

// MaxWSMessageBytes bounds one message after fragment reassembly. It matches
// the Hub's user-facing read limit, so a message that survives the user edge
// also survives the provider edge; without a bound a provider could make the
// Hub allocate arbitrarily much by sending an endless continuation stream.
const MaxWSMessageBytes = 16 << 20

// ErrWSProtocol reports a frame stream that violates RFC 6455. It is terminal:
// once a stream has produced it, nothing later in the stream can be trusted.
var ErrWSProtocol = errors.New("websocket protocol error")

// MaskClientFrame wraps a provider-bound payload in a legal MASKED client data
// frame.
//
// A WS client must mask every frame it sends. The TEE relays the Hub's uplink
// verbatim into the provider socket, so the Hub — which owns frame semantics —
// must hand the TEE bytes that already decode as a legal masked client frame.
// Otherwise the provider's own parser rejects them ("bad MASK", "bad opcode"),
// which is exactly the failure this fixes.
//
// The mask key is random per frame as the RFC intends: a fixed key is legal to
// a parser but weakens the masking a proxy relies on, and it is a stable
// fingerprint on every frame the deployment sends.
func MaskClientFrame(opcode byte, payload []byte) []byte {
	// Header is at most 2 (FIN+opcode+length) + 8 (64-bit length) + 4 (mask key)
	// = 14 bytes; the extra body always fits without a realloc.
	buf := make([]byte, 0, len(payload)+14)
	buf = append(buf, 0x80|opcode) // FIN + opcode
	n := len(payload)
	switch {
	case n < 126:
		buf = append(buf, 0x80|byte(n)) // MASK set, 7-bit length
	case n <= 0xffff:
		buf = append(buf, 0x80|126, byte(n>>8), byte(n))
	default:
		buf = append(buf, 0x80|127,
			byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	var key [4]byte
	if _, err := rand.Read(key[:]); err != nil {
		// crypto/rand does not fail on a supported platform; a fixed key keeps
		// the frame legal rather than failing an otherwise healthy session.
		copy(key[:], []byte{0x55, 0xaa, 0x12, 0x34})
	}
	buf = append(buf, key[:]...)
	for i, b := range payload {
		buf = append(buf, b^key[i%4])
	}
	return buf
}

// WsFrame is one decoded frame from a provider (server) frame stream. Data
// frames have already been reassembled across continuation frames, so a
// consumer never sees a partial message: a fragmented JSON object arrives as
// one frame, exactly as the peer wrote it.
type WsFrame struct {
	Opcode byte
	Data   []byte
	// Terminal is true for a close frame: the peer asked to close, so nothing
	// after it in the stream has meaning and the decoder stops decoding.
	Terminal bool
}

// WsFrameDecoder incrementally decodes the unmasked frame stream the TEE relays
// back from the provider. A tunnel Binary message can split or bundle frames, so
// it buffers a partial head between Feed calls and yields only complete frames.
// Provider (server) frames are unmasked; the decoder also accepts masked frames
// so a misbehaving peer degrades to a normal close rather than a hang.
type WsFrameDecoder struct {
	buf    []byte
	frag   []byte // accumulated payload of an unfinished fragmented message
	fragOp byte
	// stopped is set by a close frame or a protocol error. Nothing after that
	// point is decoded, so a truncated or hostile tail cannot be mistaken for
	// more messages.
	stopped bool
}

func NewWsFrameDecoder() *WsFrameDecoder { return &WsFrameDecoder{} }

// Feed appends bytes and returns every complete message it can decode, leaving
// any partial tail buffered. A fragmented message is reassembled and returned
// once its FIN frame arrives. After a close frame the decoder stops and returns
// what it already has; subsequent Feed calls return nil.
//
// An error means the stream violated the protocol; it is returned with the
// frames decoded before the violation, and the decoder is stopped.
func (d *WsFrameDecoder) Feed(p []byte) ([]WsFrame, error) {
	if d.stopped {
		return nil, nil
	}
	d.buf = append(d.buf, p...)
	var out []WsFrame
	for !d.stopped && len(d.buf) >= 2 {
		b0, b1 := d.buf[0], d.buf[1]
		fin := b0&0x80 != 0
		opcode := b0 & 0x0f
		masked := b1&0x80 != 0
		n := uint64(b1 & 0x7f)
		head := 2

		// RSV bits are an extension the TEE explicitly refuses to negotiate;
		// a frame that sets one is not something this relay can pass through.
		if b0&0x70 != 0 {
			return out, d.fail(fmt.Errorf("%w: reserved bits set (0x%02x)", ErrWSProtocol, b0))
		}
		if !validWSOpcode(opcode) {
			return out, d.fail(fmt.Errorf("%w: unknown opcode 0x%x", ErrWSProtocol, opcode))
		}
		control := opcode >= 0x8
		if control && (!fin || n > 125) {
			return out, d.fail(fmt.Errorf("%w: control frame with fin=%t length=%d", ErrWSProtocol, fin, n))
		}

		switch n {
		case 126:
			if len(d.buf) < head+2 {
				return out, nil
			}
			n = uint64(d.buf[head])<<8 | uint64(d.buf[head+1])
			head += 2
		case 127:
			if len(d.buf) < head+8 {
				return out, nil
			}
			n = 0
			for j := 0; j < 8; j++ {
				n = n<<8 | uint64(d.buf[head+j])
			}
			head += 8
			// A length with the top bit set is invalid, and anything above the
			// message cap can never be delivered.
			if n>>63 != 0 {
				return out, d.fail(fmt.Errorf("%w: frame length has the high bit set", ErrWSProtocol))
			}
		}
		if n > MaxWSMessageBytes {
			return out, d.fail(fmt.Errorf("%w: message exceeds %d bytes", ErrWSProtocol, MaxWSMessageBytes))
		}
		if opcode == WSOpContinuation && uint64(len(d.frag))+n > MaxWSMessageBytes {
			// A control frame may sit between fragments, so the accumulated
			// bound applies only to the message the continuation extends.
			return out, d.fail(fmt.Errorf("%w: message exceeds %d bytes", ErrWSProtocol, MaxWSMessageBytes))
		}

		var key []byte
		if masked {
			if len(d.buf) < head+4 {
				return out, nil
			}
			key = d.buf[head : head+4]
			head += 4
		}
		if uint64(len(d.buf)) < uint64(head)+n {
			return out, nil // partial payload; wait for more bytes
		}

		payload := make([]byte, n)
		copy(payload, d.buf[head:head+int(n)])
		if masked {
			for j := range payload {
				payload[j] ^= key[j%4]
			}
		}
		d.buf = d.buf[head+int(n):]

		if control {
			f := WsFrame{Opcode: opcode, Data: payload}
			if opcode == WSOpClose {
				f.Terminal = true
				d.stopped = true
				d.buf = nil
				d.frag = nil
			}
			out = append(out, f)
			continue
		}

		switch opcode {
		case WSOpContinuation:
			if d.fragOp == 0 {
				return out, d.fail(fmt.Errorf("%w: continuation without a fragmented message", ErrWSProtocol))
			}
			d.frag = append(d.frag, payload...)
			if fin {
				if d.fragOp == WSOpText && !utf8.Valid(d.frag) {
					// RFC 6455 §8.1: a text message must be valid UTF-8, and the
					// receiver must fail the connection otherwise. The Hub
					// re-emits the assembled message, so passing it on would push
					// the failure onto the user's client.
					return out, d.fail(fmt.Errorf("%w: text message is not valid UTF-8", ErrWSProtocol))
				}
				out = append(out, WsFrame{Opcode: d.fragOp, Data: d.frag})
				d.frag = nil
				d.fragOp = 0
			}
		case WSOpText, WSOpBinary:
			if d.fragOp != 0 {
				return out, d.fail(fmt.Errorf("%w: new data frame inside a fragmented message", ErrWSProtocol))
			}
			if fin {
				if opcode == WSOpText && !utf8.Valid(payload) {
					return out, d.fail(fmt.Errorf("%w: text message is not valid UTF-8", ErrWSProtocol))
				}
				out = append(out, WsFrame{Opcode: opcode, Data: payload})
				continue
			}
			d.fragOp = opcode
			d.frag = payload
		}
	}
	return out, nil
}

// fail stops the decoder and returns err.
func (d *WsFrameDecoder) fail(err error) error {
	d.stopped = true
	d.buf = nil
	d.frag = nil
	return err
}

func validWSOpcode(op byte) bool {
	switch op {
	case WSOpContinuation, WSOpText, WSOpBinary, WSOpClose, WSOpPing, WSOpPong:
		return true
	}
	return false
}

// ParseClosePayload decodes the body of a close frame. ok is false when the
// payload is malformed or carries a code the RFC reserves for local use, in
// which case the caller should answer with a protocol-error close rather than
// echo a code that must never appear on the wire.
func ParseClosePayload(payload []byte) (code uint16, reason string, ok bool) {
	if len(payload) == 0 {
		// No status code. 1005 is the value used locally to mean exactly that;
		// it must never be sent back.
		return 1005, "", true
	}
	if len(payload) == 1 {
		return 0, "", false
	}
	code = binary.BigEndian.Uint16(payload[:2])
	reason = string(payload[2:])
	if !utf8.ValidString(reason) {
		return 0, "", false
	}
	switch {
	case code >= 1000 && code <= 1003:
	case code >= 1007 && code <= 1014:
	case code >= 3000 && code <= 4999:
	default:
		// 1004, 1005, 1006, 1015 and the unassigned 0-999 range are not valid
		// on the wire.
		return 0, "", false
	}
	return code, reason, true
}

// ClosePayload renders a close body. A zero code means "no status", which is
// what a peer that closed without one is answered with.
func ClosePayload(code uint16, reason string) []byte {
	if code == 0 || code == 1005 {
		return nil
	}
	// The control-frame limit leaves 125 bytes; two are the code.
	if len(reason) > 123 {
		reason = reason[:123]
		// Do not cut a UTF-8 sequence in half.
		for len(reason) > 0 && !utf8.ValidString(reason) {
			reason = reason[:len(reason)-1]
		}
	}
	payload := make([]byte, 2, 2+len(reason))
	binary.BigEndian.PutUint16(payload, code)
	return append(payload, reason...)
}

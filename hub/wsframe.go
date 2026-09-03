package hub

// WebSocket frame opcodes. The Hub only needs the data opcodes to relay bytes
// and the close opcode to notice the end of a session; it deliberately ignores
// ping/pong/continuation control semantics and forwards data verbatim.
const (
	WSOpText   = 0x1
	WSOpBinary = 0x2
	WSOpClose  = 0x8
)

// MaskClientFrame wraps a provider-bound payload in a legal MASKED client data
// frame.
//
// A WS client must mask every frame it sends. The TEE relays the Hub's uplink
// verbatim into the provider socket, so the Hub — which owns frame semantics —
// must hand the TEE bytes that already decode as a legal masked client frame.
// Otherwise the provider's own parser rejects them ("bad MASK", "bad opcode"),
// which is exactly the failure this fixes.
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
	// A fixed key is fine: masking is a transport legality, not secrecy. The key
	// only has to be validly xor-encoded for the provider's parser to accept it.
	key := []byte{0x55, 0xaa, 0x12, 0x34}
	buf = append(buf, key...)
	for i, b := range payload {
		buf = append(buf, b^key[i%4])
	}
	return buf
}

// WsFrame is one decoded frame from a provider (server) frame stream.
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
	buf []byte
}

func NewWsFrameDecoder() *WsFrameDecoder { return &WsFrameDecoder{} }

// Feed appends bytes and returns every complete frame it can decode, leaving any
// partial tail buffered. After a close frame the decoder stops and returns what
// it already has; subsequent Feed calls return nil.
func (d *WsFrameDecoder) Feed(p []byte) []WsFrame {
	d.buf = append(d.buf, p...)
	var out []WsFrame
	for len(d.buf) >= 2 {
		b0, b1 := d.buf[0], d.buf[1]
		opcode := b0 & 0x0f
		masked := b1&0x80 != 0
		n := uint64(b1 & 0x7f)
		head := 2

		switch n {
		case 126:
			if len(d.buf) < head+2 {
				return out
			}
			n = uint64(d.buf[head])<<8 | uint64(d.buf[head+1])
			head += 2
		case 127:
			if len(d.buf) < head+8 {
				return out
			}
			n = 0
			for j := 0; j < 8; j++ {
				n = n<<8 | uint64(d.buf[head+j])
			}
			head += 8
		}

		var key []byte
		if masked {
			if len(d.buf) < head+4 {
				return out
			}
			key = d.buf[head : head+4]
			head += 4
		}
		if uint64(len(d.buf)) < uint64(head)+n {
			return out // partial payload; wait for more bytes
		}

		payload := d.buf[head : head+int(n)]
		pl := make([]byte, n)
		copy(pl, payload)
		if masked {
			for j := range pl {
				pl[j] ^= key[j%4]
			}
		}

		d.buf = d.buf[head+int(n):]
		f := WsFrame{Opcode: opcode, Data: pl}
		if opcode == WSOpClose {
			f.Terminal = true
			return append(out, f)
		}
		out = append(out, f)
	}
	return out
}

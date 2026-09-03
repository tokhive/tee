package hub

import (
	"bytes"
	"testing"
)

// TestMaskClientFrameRoundTrip builds a masked client frame and decodes it back
// with a frame decoder; the payload must survive the trip exactly. This is the
// property the whole session seam depends on: a hub frame must parse cleanly on
// the provider side.
func TestMaskClientFrameRoundTrip(t *testing.T) {
	payload := []byte(`{"event":"conversation.item.create"}`)
	raw := MaskClientFrame(WSOpText, payload)

	d := NewWsFrameDecoder()
	frames := d.Feed(raw)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	if frames[0].Opcode != WSOpText {
		t.Fatalf("opcode = %d, want %d", frames[0].Opcode, WSOpText)
	}
	if frames[0].Terminal {
		t.Fatal("unexpected terminal frame")
	}
	if !bytes.Equal(frames[0].Data, payload) {
		t.Fatalf("payload = %q, want %q", frames[0].Data, payload)
	}
}

// unmaskedFrame builds the unmasked server frame a provider writes, since the
// downlink side of the tunnel carries server frames.
func unmaskedFrame(opcode byte, payload []byte) []byte {
	buf := []byte{0x80 | opcode} // FIN + opcode, no MASK
	n := len(payload)
	switch {
	case n < 126:
		buf = append(buf, byte(n))
	case n <= 0xffff:
		buf = append(buf, 126, byte(n>>8), byte(n))
	default:
		buf = append(buf, 127,
			byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(buf, payload...)
}

// TestWsFrameDecoderSplitting feeds a stream that splits one frame's bytes across
// several calls and bundles several frames into one call — the two shapes a
// byte-relay tunnel produces. Every frame must still decode exactly.
func TestWsFrameDecoderSplitting(t *testing.T) {
	a := []byte(`{"event":"session.created"}`)
	b := []byte(`{"event":"response.audio.delta","data":"abc"}`)
	sa, sb := unmaskedFrame(WSOpText, a), unmaskedFrame(WSOpText, b)

	// Split: feed the two frames one byte at a time.
	combined := append(append([]byte{}, sa...), sb...)
	d := NewWsFrameDecoder()
	var got []WsFrame
	for _, b := range combined {
		got = append(got, d.Feed([]byte{b})...)
	}
	if len(got) != 2 {
		t.Fatalf("got %d frames from byte-at-a-time feed, want 2", len(got))
	}
	if !bytes.Equal(got[0].Data, a) || !bytes.Equal(got[1].Data, b) {
		t.Fatalf("split framing corrupted payloads: %q / %q", got[0].Data, got[1].Data)
	}

	// Bundle: both frames in a single call.
	d2 := NewWsFrameDecoder()
	got2 := d2.Feed(append(append([]byte{}, sa...), sb...))
	if len(got2) != 2 {
		t.Fatalf("got %d frames from a bundled call, want 2", len(got2))
	}
	if !bytes.Equal(got2[0].Data, a) || !bytes.Equal(got2[1].Data, b) {
		t.Fatal("bundled framing corrupted payloads")
	}
}

// TestWsFrameDecoderCloseStop ensures a close frame terminates decoding: frames
// after it are not surfaced, and the close frame is marked terminal.
func TestWsFrameDecoderCloseStop(t *testing.T) {
	data := []byte(`{"event":"response.done"}`)
	closeFrame := []byte{0x88, 0x02, 0x03, 0xe8} // FIN + close, len 2, code 1000

	d := NewWsFrameDecoder()
	all := append(unmaskedFrame(WSOpText, data), closeFrame...)
	got := d.Feed(all)
	if len(got) != 2 {
		t.Fatalf("got %d frames, want data + close = 2", len(got))
	}
	if !got[1].Terminal {
		t.Fatal("second frame should be marked terminal (close)")
	}
}

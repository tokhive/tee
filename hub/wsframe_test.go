package hub

import (
	"bytes"
	"errors"
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
	frames, err := d.Feed(raw)
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
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
	return frameWith(true, opcode, payload)
}

func frameWith(fin bool, opcode byte, payload []byte) []byte {
	first := opcode
	if fin {
		first |= 0x80
	}
	buf := []byte{first}
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
		frames, err := d.Feed([]byte{b})
		if err != nil {
			t.Fatalf("feed: %v", err)
		}
		got = append(got, frames...)
	}
	if len(got) != 2 {
		t.Fatalf("got %d frames from byte-at-a-time feed, want 2", len(got))
	}
	if !bytes.Equal(got[0].Data, a) || !bytes.Equal(got[1].Data, b) {
		t.Fatalf("split framing corrupted payloads: %q / %q", got[0].Data, got[1].Data)
	}

	// Bundle: both frames in a single call.
	d2 := NewWsFrameDecoder()
	got2, err := d2.Feed(append(append([]byte{}, sa...), sb...))
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
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
	got, err := d.Feed(all)
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d frames, want data + close = 2", len(got))
	}
	if !got[1].Terminal {
		t.Fatal("second frame should be marked terminal (close)")
	}
	if more, err := d.Feed(unmaskedFrame(WSOpText, data)); err != nil || len(more) != 0 {
		t.Fatalf("decoder surfaced frames after close: %v / %v", more, err)
	}
}

// TestWsFrameDecoderReassemblesFragments covers the shape a provider uses when
// it splits one JSON event across several frames: the Hub must deliver one
// message, because re-emitting the fragments as separate messages would hand a
// client two invalid JSON documents.
func TestWsFrameDecoderReassemblesFragments(t *testing.T) {
	first := frameWith(false, WSOpText, []byte(`{"event":"res`))
	ping := unmaskedFrame(WSOpPing, []byte("keepalive"))
	last := frameWith(true, WSOpContinuation, []byte(`ponse.done"}`))

	d := NewWsFrameDecoder()
	got, err := d.Feed(append(append(append([]byte{}, first...), ping...), last...))
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d frames, want ping + reassembled text", len(got))
	}
	if got[0].Opcode != WSOpPing || string(got[0].Data) != "keepalive" {
		t.Fatalf("ping = %+v", got[0])
	}
	if got[1].Opcode != WSOpText || string(got[1].Data) != `{"event":"response.done"}` {
		t.Fatalf("reassembled = %+v", got[1])
	}
}

func TestWsFrameDecoderRejectsProtocolViolations(t *testing.T) {
	tests := []struct {
		name  string
		bytes []byte
	}{
		{"reserved bit", []byte{0xC1, 0x00}},
		{"unknown opcode", unmaskedFrame(0x3, nil)},
		{"continuation without start", frameWith(true, WSOpContinuation, []byte("x"))},
		{"text inside a fragmented message", append(
			frameWith(false, WSOpText, []byte("a")),
			unmaskedFrame(WSOpText, []byte("b"))...)},
		{"fragmented control frame", frameWith(false, WSOpPing, nil)},
		{"oversized control frame", unmaskedFrame(WSOpPing, bytes.Repeat([]byte("x"), 126))},
		{"oversized data frame", unmaskedFrame(WSOpBinary, bytes.Repeat([]byte("x"), MaxWSMessageBytes+1))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := NewWsFrameDecoder()
			if _, err := d.Feed(tc.bytes); !errors.Is(err, ErrWSProtocol) {
				t.Fatalf("err = %v, want ErrWSProtocol", err)
			}
			// Once violated the decoder is terminal.
			if frames, err := d.Feed(unmaskedFrame(WSOpText, []byte("ok"))); err != nil || len(frames) != 0 {
				t.Fatalf("decoder continued after a protocol error: %v / %v", frames, err)
			}
		})
	}
}

func TestParseClosePayload(t *testing.T) {
	code, reason, ok := ParseClosePayload([]byte{0x03, 0xE8, 'b', 'y', 'e'})
	if !ok || code != 1000 || reason != "bye" {
		t.Fatalf("got %d %q %t", code, reason, ok)
	}
	if code, reason, ok := ParseClosePayload(nil); !ok || code != 1005 || reason != "" {
		t.Fatalf("empty close: %d %q %t", code, reason, ok)
	}
	for _, bad := range [][]byte{
		{0x03},             // one-byte payload
		{0x03, 0xEC},       // 1004, reserved
		{0x03, 0xED},       // 1005, must not appear on the wire
		{0x03, 0xEF, 0xff}, // invalid UTF-8 reason
	} {
		if _, _, ok := ParseClosePayload(bad); ok {
			t.Fatalf("accepted invalid close payload %x", bad)
		}
	}
}

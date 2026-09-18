package tee

import (
	"io"
	"strings"
	"testing"
)

// TestSSEStreamDecodesFrames pins the framing rules the writer in rpc.go emits
// and every reader of the stream depends on: data lines join with \n, each
// loses exactly one leading space, an empty data line is a real (empty) chunk,
// a frame that never got its closing blank line is still delivered, and a blank
// separator or a comment dispatches nothing.
func TestSSEStreamDecodesFrames(t *testing.T) {
	stream := NewSSEStream(strings.NewReader(
		"\n" +
			": a comment\n" +
			"event: start\r\ndata: {\"status\":200}\r\n\r\n" +
			"data: one\ndata: two\n\n" +
			"data:\n\n" +
			"data:  leading  spaces \n\n" +
			"event: end\n\n" +
			"event: receipt\ndata: eyJ4IjoxfQ==",
	))
	want := []SSEEvent{
		{Type: EventStart, Data: `{"status":200}`, HasData: true},
		{Data: "one\ntwo", HasData: true},
		{HasData: true},
		// The writer emits one space after "data:" and the reader removes
		// exactly one, so a payload's own leading spaces survive.
		{Data: " leading  spaces ", HasData: true},
		{Type: "end"},
		{Type: EventReceipt, Data: "eyJ4IjoxfQ==", HasData: true},
	}
	for i, want := range want {
		got, err := stream.Next()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if got != want {
			t.Errorf("frame %d = %+v, want %+v", i, got, want)
		}
	}
	if got, err := stream.Next(); err != io.EOF {
		t.Fatalf("after the last frame, Next = (%+v, %v), want io.EOF", got, err)
	}
}

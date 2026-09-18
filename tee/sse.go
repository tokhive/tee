package tee

import (
	"bufio"
	"io"
	"strings"
)

// SSEEvent is one dispatched frame of a streaming response body. Its Type is
// one of this package's event names (EventStart, EventReceipt, EventError) or
// empty for the plain data frames that carry response chunks.
type SSEEvent struct {
	// Type is the frame's event: field, empty when it carried none.
	Type string
	// Data is the frame's data: lines joined with \n, each with exactly one
	// leading space removed, which is the convention rpc.go's writer emits.
	Data string
	// HasData distinguishes a frame with no data line from one carrying a
	// single empty line. Downstream that difference is a response byte:
	// StreamingHasher counts an empty chunk, so a reader that conflated the two
	// would produce a chunk count and stream hash the receipt disagrees with.
	HasData bool
}

// SSEStream decodes a streaming response body into frames.
//
// The framing rules live here, beside the writer that produces them, because
// more than one reader consumes the same stream: the Hub, which has to settle
// against exactly the bytes it delivered, and the benchmark, which times their
// arrival. A second copy of these rules is a second opinion about what a chunk
// is — the very thing the receipt's stream hash would then disagree with.
type SSEStream struct {
	reader *bufio.Reader
}

// NewSSEStream returns a decoder reading r.
func NewSSEStream(r io.Reader) *SSEStream {
	return &SSEStream{reader: bufio.NewReader(r)}
}

// Next returns the next frame, reporting io.EOF once the stream is exhausted.
// A frame that arrives without its terminating blank line — a stream cut off
// mid-flight — is still delivered, so a reader keeps the bytes it did receive.
// Frames carrying neither an event nor data (blank separators, comments) are
// skipped rather than reported, since nothing downstream can act on them.
func (s *SSEStream) Next() (SSEEvent, error) {
	var (
		event     SSEEvent
		data      strings.Builder
		dataLines int
		seen      bool
	)
	for {
		line, err := s.reader.ReadString('\n')
		trimmed := strings.TrimRight(line, "\r\n")
		switch {
		case trimmed == "":
			if seen {
				event.Data, event.HasData = data.String(), dataLines > 0
				return event, nil
			}
		case strings.HasPrefix(trimmed, "event:"):
			seen = true
			event.Type = strings.TrimSpace(strings.TrimPrefix(trimmed, "event:"))
		case strings.HasPrefix(trimmed, "data:"):
			seen = true
			// Consecutive data lines join with \n, and each loses exactly one
			// leading space. Nothing else is touched: the payload is what the
			// receipt hashes, so trimming it would corrupt the stream.
			if dataLines > 0 {
				data.WriteByte('\n')
			}
			dataLines++
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(trimmed, "data:"), " "))
		}
		if err != nil {
			if seen {
				event.Data, event.HasData = data.String(), dataLines > 0
				return event, nil
			}
			return SSEEvent{}, io.EOF
		}
	}
}

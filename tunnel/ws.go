package tunnel

import (
	"sync"

	"github.com/gorilla/websocket"
)

// wsStream adapts a WebSocket channel to the continuous io.ReadWriter the
// Multiplexer needs. WebSocket delivers bounded messages; the tunnel wants a
// byte stream. Read therefore concatenates inbound Binary messages into one
// continuous stream (buffering whatever a single Read leaves over), and Write
// sends each buffer as one Binary message. The tunnel's 13-byte framing lives
// inside the message bytes, so this wrapper is purely a carrier — it never
// interprets a byte.
type wsStream struct {
	conn    *websocket.Conn
	rbuf    []byte
	writeMu sync.Mutex
}

// WrapWS wraps a WebSocket connection as a stream suitable for tunnel.New.
func WrapWS(conn *websocket.Conn) ioReadWriteCloser {
	return &wsStream{conn: conn}
}

func (w *wsStream) Read(p []byte) (int, error) {
	for len(w.rbuf) == 0 {
		_, msg, err := w.conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		if len(msg) == 0 {
			continue
		}
		w.rbuf = msg
	}
	n := copy(p, w.rbuf)
	w.rbuf = w.rbuf[n:]
	return n, nil
}

func (w *wsStream) Write(p []byte) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if err := w.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsStream) Close() error { return w.conn.Close() }

// ioReadWriteCloser is the interface both the raw streams and the WS wrapper
// satisfy, so New can take a WebSocket-backed stream or a net.Pipe without a
// type switch.
type ioReadWriteCloser interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

package tunnel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// TestOverWebSocket drives a full multiplexed tunnel through a real WebSocket
// handshake: the client dials an httptest server that wraps each accepted
// connection in a tunnel.Multiplexer echoing every opened stream. This proves
// the wsStream wrapper turns WS messages into a continuous byte stream that the
// 13-byte framing survives intact in both directions.
func TestOverWebSocket(t *testing.T) {
	var upgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		m := New(WrapWS(c), Low)
		m.Serve(func(s *Stream, _ []byte) {
			io.Copy(s, s) // echo
			_ = s.Close()
		})
	}))
	defer server.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	client := New(WrapWS(conn), High)
	defer client.Close()

	s, err := client.Dial([]byte("over-ws-open"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	msg := "realtime through a websocket tunnel"
	if _, err := s.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(msg))
	if _, err := io.ReadFull(s, back); err != nil {
		t.Fatal(err)
	}
	if string(back) != msg {
		t.Fatalf("echo mismatch: %q", back)
	}
}

// TestWSReadLimit confirms a peer message larger than the read limit is refused
// with an error rather than silently buffered: the relay tunnel is a boundary a
// malicious or corrupt peer could otherwise use to drive unbounded allocation.
func TestWSReadLimit(t *testing.T) {
	var upgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = c.WriteMessage(websocket.BinaryMessage, make([]byte, wsReadLimit+1))
	}))
	defer server.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := WrapWS(conn)
	defer s.Close()

	var buf [16]byte
	if _, err := s.Read(buf[:]); err == nil {
		t.Fatal("expected an error reading a message larger than wsReadLimit")
	}
}

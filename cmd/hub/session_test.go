package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/tokhive/tee/hub"
)

// sessionPair returns the two ends of one real WebSocket handshake: the server
// side (what sessionHandler wraps in a sessionLink) and the client side (the
// user). Driving the adapter through a real conn is the point — frame chunking,
// masking, deadlines and close handshakes are all gorilla's behaviour, and a
// fake conn would test the fake.
func sessionPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	serverSide := make(chan *websocket.Conn, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverSide <- conn
	}))
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		srv.Close()
		t.Fatalf("dial test session: %v", err)
	}

	var server *websocket.Conn
	select {
	case server = <-serverSide:
	case <-time.After(2 * time.Second):
		_ = client.Close()
		srv.Close()
		t.Fatal("server did not complete the WebSocket upgrade")
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		srv.Close()
	})
	return server, client
}

// serverFrame builds one unmasked provider (server) frame. Providers do not
// mask; the link's decoder accepts exactly what a real provider writes.
func serverFrame(fin bool, opcode byte, payload []byte) []byte {
	first := opcode
	if fin {
		first |= 0x80
	}
	n := len(payload)
	var out []byte
	switch {
	case n < 126:
		out = []byte{first, byte(n)}
	case n <= 0xffff:
		out = []byte{first, 126, byte(n >> 8), byte(n)}
	default:
		out = []byte{first, 127,
			0, 0, 0, 0,
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(out, payload...)
}

func mustFeed(t *testing.T, dec *hub.WsFrameDecoder, raw []byte) []hub.WsFrame {
	t.Helper()
	frames, err := dec.Feed(raw)
	if err != nil {
		t.Fatalf("decode provider frame stream: %v", err)
	}
	return frames
}

// TestSessionLinkReadReplaysTheFirstFrameAcrossChunks pins the uplink shape: the
// message already read for model selection still reaches the provider first, and
// a message larger than one relay buffer is handed out as one intact masked
// frame across several Read calls, never as a truncated or re-framed message.
func TestSessionLinkReadReplaysTheFirstFrameAcrossChunks(t *testing.T) {
	server, client := sessionPair(t)
	first := []byte(`{"model":"m"}`)
	link := &sessionLink{conn: server, first: first, firstOp: hub.WSOpText}
	link.BindSession(io.Discard)
	defer link.ReleaseSession()

	big := bytes.Repeat([]byte("x"), 200_000)
	go func() { _ = client.WriteMessage(websocket.BinaryMessage, big) }()

	want := len(hub.MaskClientFrame(hub.WSOpText, first)) + len(hub.MaskClientFrame(hub.WSOpBinary, big))
	got := make([]byte, 0, want)
	buf := make([]byte, 32*1024)
	for len(got) < want {
		n, err := link.Read(buf)
		if err != nil {
			t.Fatalf("read uplink after %d/%d bytes: %v", len(got), want, err)
		}
		if n == 0 {
			t.Fatal("Read returned no bytes and no error")
		}
		got = append(got, buf[:n]...)
	}

	frames := mustFeed(t, hub.NewWsFrameDecoder(), got)
	if len(frames) != 2 {
		t.Fatalf("decoded %d uplink messages, want 2", len(frames))
	}
	if frames[0].Opcode != hub.WSOpText || !bytes.Equal(frames[0].Data, first) {
		t.Fatalf("first uplink message = op %#x payload %q, want the replayed first frame", frames[0].Opcode, frames[0].Data)
	}
	if frames[1].Opcode != hub.WSOpBinary || !bytes.Equal(frames[1].Data, big) {
		t.Fatalf("second uplink message = op %#x length %d, want one binary message of %d bytes", frames[1].Opcode, len(frames[1].Data), len(big))
	}
}

// TestSessionLinkWriteRelaysDownlinkAndAnswersControlFrames pins the provider→user
// half: fragments are reassembled into one user message, a provider ping is
// answered through the tunnel (the only path the provider can see), and a
// provider close becomes the user's close.
func TestSessionLinkWriteRelaysDownlinkAndAnswersControlFrames(t *testing.T) {
	server, client := sessionPair(t)
	var tunnel bytes.Buffer
	link := &sessionLink{conn: server, tunnel: &tunnel}

	stream := append(
		serverFrame(false, hub.WSOpText, []byte("hel")),
		serverFrame(true, hub.WSOpContinuation, []byte("lo"))...,
	)
	stream = append(stream, serverFrame(true, hub.WSOpBinary, []byte{0x00, 0x01})...)
	stream = append(stream, serverFrame(true, hub.WSOpPing, []byte("hb"))...)
	if n, err := link.Write(stream); err != nil || n != len(stream) {
		t.Fatalf("write downlink = %d, %v; want %d, nil", n, err, len(stream))
	}

	mt, msg, err := client.ReadMessage()
	if err != nil {
		t.Fatalf("read first user message: %v", err)
	}
	if mt != websocket.TextMessage || string(msg) != "hello" {
		t.Fatalf("first user message = type %d %q, want one reassembled text \"hello\"", mt, msg)
	}
	mt, msg, err = client.ReadMessage()
	if err != nil {
		t.Fatalf("read second user message: %v", err)
	}
	if mt != websocket.BinaryMessage || !bytes.Equal(msg, []byte{0x00, 0x01}) {
		t.Fatalf("second user message = type %d %v, want the provider's binary message", mt, msg)
	}

	pongs := mustFeed(t, hub.NewWsFrameDecoder(), tunnel.Bytes())
	if len(pongs) != 1 || pongs[0].Opcode != hub.WSOpPong || string(pongs[0].Data) != "hb" {
		t.Fatalf("tunnel frames = %+v, want exactly one pong carrying \"hb\"", pongs)
	}

	link.Write(serverFrame(true, hub.WSOpClose, hub.ClosePayload(websocket.CloseNormalClosure, "bye")))
	_, _, err = client.ReadMessage()
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("user read after provider close = %v, want a close frame", err)
	}
	if ce.Code != websocket.CloseNormalClosure || ce.Text != "bye" {
		t.Fatalf("user close = %d %q, want 1000 \"bye\"", ce.Code, ce.Text)
	}
}

// TestSessionLinkReadClosesTheProviderWhenTheUserLeaves pins the billing-critical
// direction: a user close frame is echoed into the tunnel, with the user's own
// code when it is legal on the wire.
func TestSessionLinkReadClosesTheProviderWhenTheUserLeaves(t *testing.T) {
	server, client := sessionPair(t)
	var tunnel bytes.Buffer
	link := &sessionLink{conn: server, tunnel: &tunnel}

	go func() {
		_ = client.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseGoingAway, "leaving"))
	}()
	if _, err := link.Read(make([]byte, 64)); err == nil {
		t.Fatal("Read after the user's close returned no error")
	}

	frames := mustFeed(t, hub.NewWsFrameDecoder(), tunnel.Bytes())
	if len(frames) != 1 || frames[0].Opcode != hub.WSOpClose {
		t.Fatalf("tunnel frames = %+v, want exactly one close frame", frames)
	}
	code, reason, ok := hub.ParseClosePayload(frames[0].Data)
	if !ok || code != websocket.CloseGoingAway || reason != "leaving" {
		t.Fatalf("upstream close = code %d reason %q ok=%t, want 1001 \"leaving\"", code, reason, ok)
	}
}

// TestSessionLinkFinishSendsAnOrderlyUserClose covers both endings: a clean
// session end after a provider socket drop becomes a normal close, and a failed
// session becomes an internal-error close naming the protocol mismatch.
func TestSessionLinkFinishSendsAnOrderlyUserClose(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		code   int
		reason string
	}{
		{name: "clean end", err: nil, code: websocket.CloseNormalClosure},
		{
			name:   "protocol mismatch",
			err:    fmt.Errorf("relay: %w", hub.ErrSessionProtocolMismatch),
			code:   websocket.CloseInternalServerErr,
			reason: "provider did not accept the negotiated subprotocol",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := sessionPair(t)
			link := &sessionLink{conn: server}
			link.finish(tc.err)

			_, _, err := client.ReadMessage()
			var ce *websocket.CloseError
			if !errors.As(err, &ce) {
				t.Fatalf("user read = %v, want a close frame", err)
			}
			if ce.Code != tc.code {
				t.Fatalf("close code = %d, want %d", ce.Code, tc.code)
			}
			if tc.reason != "" && ce.Text != tc.reason {
				t.Fatalf("close reason = %q, want %q", ce.Text, tc.reason)
			}
		})
	}
}

// TestBuildSessionCarriesTheNegotiatedProtocolAndConfiguredPath pins the spec the
// TEE receives: the upstream path is the deployment's (not the Hub's user-facing
// route), and the user's subprotocol is offered to the provider only when there
// is one.
func TestBuildSessionCarriesTheNegotiatedProtocolAndConfiguredPath(t *testing.T) {
	cfg := serveConfig{
		Host:        "api.example:443",
		SessionPath: "/v1/custom-realtime",
		Query:       "k=v",
		Max:         4096,
	}
	h := &sessionHandler{cfg: cfg}

	spec, err := h.buildSession("openai", "realtime.v1")
	if err != nil {
		t.Fatalf("build session: %v", err)
	}
	if spec.Method != "GET" || !spec.Stream || !spec.Session {
		t.Fatalf("spec = %s stream=%t session=%t, want GET stream session", spec.Method, spec.Stream, spec.Session)
	}
	if spec.Path != "/v1/custom-realtime" {
		t.Fatalf("upstream path = %q, want the configured path", spec.Path)
	}
	if spec.Host != "api.example:443" || spec.Query != "k=v" || spec.MaxResponseBytes != 4096 {
		t.Fatalf("spec = host %q query %q max %d, want the deployment's routing", spec.Host, spec.Query, spec.MaxResponseBytes)
	}
	if got := spec.Headers["sec-websocket-protocol"]; got != "realtime.v1" {
		t.Fatalf("offered subprotocol = %q, want realtime.v1", got)
	}

	spec, err = h.buildSession("openai", "")
	if err != nil {
		t.Fatalf("build session without a subprotocol: %v", err)
	}
	if _, ok := spec.Headers["sec-websocket-protocol"]; ok {
		t.Fatalf("headers = %v, want no subprotocol offer when the user negotiated none", spec.Headers)
	}

	cfg.SessionPath = ""
	h = &sessionHandler{cfg: cfg}
	spec, err = h.buildSession("openai", "")
	if err != nil {
		t.Fatalf("build session with the default path: %v", err)
	}
	if spec.Path != realtimePath {
		t.Fatalf("upstream path = %q, want the built-in %q", spec.Path, realtimePath)
	}
}

// TestSessionHandlerRefusesAMissingTenantBeforeUpgrade pins the order: an
// unauthorized caller gets a plain 401, not a WebSocket that opens and dies.
func TestSessionHandlerRefusesAMissingTenantBeforeUpgrade(t *testing.T) {
	h := &sessionHandler{cfg: serveConfig{}}
	req := httptest.NewRequest(http.MethodGet, sessionPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 before any upgrade", rec.Code)
	}
}

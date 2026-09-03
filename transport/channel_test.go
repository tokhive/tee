package transport

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// hostOf turns an httptest server URL into the host[:port] form a tee.Request
// expects.
func hostOf(srv *httptest.Server) string {
	return strings.TrimPrefix(srv.URL, "http://")
}

// newTestManager builds a ChannelManager that dials the provider directly (no
// agent), using the plain-text scheme so the tests can inspect bytes.
func newTestManager(t *testing.T) *ChannelManager {
	t.Helper()
	reg := NewRegistry()
	reg.Set("p", Endpoint{})
	cm, err := NewChannelManager(ChannelConfig{
		Scheme:         "http",
		AllowPlaintext: true,
		Endpoints:      reg,
	})
	if err != nil {
		t.Fatalf("NewChannelManager: %v", err)
	}
	t.Cleanup(func() { _ = cm.Close() })
	return cm
}

// testReq returns a request tagged for provider "p".
func testReq(req tee.Request) tee.Request {
	if req.Provider == "" {
		req.Provider = "p"
	}
	return req
}

// newConnCountingServer returns a server that counts every new TCP connection.
func newConnCountingServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(handler)
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &conns
}

func TestChannelBasicExchange(t *testing.T) {
	var got struct {
		method string
		path   string
		query  string
		header string
		auth   string
		body   string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.method = r.Method
		got.path = r.URL.Path
		got.query = r.URL.RawQuery
		got.header = r.Header.Get("X-Custom")
		got.auth = r.Header.Get("Authorization")
		got.body = string(body)
		fmt.Fprint(w, "hello world")
	}))
	defer srv.Close()

	cm := newTestManager(t)
	var chunks []string
	resp, err := cm.Do(context.Background(),
		testReq(tee.Request{
			Method:  "POST",
			Host:    hostOf(srv),
			Path:    "/v1/chat/completions",
			Query:   "model=glm-5&stream=true",
			Headers: map[string]string{"X-Custom": "value", "Authorization": "Bearer secret-token"},
			Body:    []byte(`{"messages":[]}`),
		}),
		func(chunk []byte) error {
			chunks = append(chunks, string(chunk))
			return nil
		})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got.method != "POST" || got.path != "/v1/chat/completions" || got.query != "model=glm-5&stream=true" {
		t.Fatalf("request line mismatch: %s %s ?%s", got.method, got.path, got.query)
	}
	if got.header != "value" {
		t.Errorf("X-Custom = %q, want %q", got.header, "value")
	}
	if got.auth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want %q", got.auth, "Bearer secret-token")
	}
	if got.body != `{"messages":[]}` {
		t.Errorf("body = %q, want %q", got.body, `{"messages":[]}`)
	}
	if joined := strings.Join(chunks, ""); joined != "hello world" {
		t.Errorf("relayed body = %q, want %q", joined, "hello world")
	}
}

func TestChannelSSEStreamRelayed(t *testing.T) {
	events := []string{"data: event-0\n\n", "data: event-1\n\n", "data: event-2\n\n"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, event := range events {
			fmt.Fprint(w, event)
			flusher.Flush()
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer srv.Close()

	cm := newTestManager(t)
	var chunks []string
	_, err := cm.Do(context.Background(),
		testReq(tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/chat/completions", Body: []byte("{}")}),
		func(chunk []byte) error {
			chunks = append(chunks, string(chunk))
			return nil
		})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("got %d chunks, want the events relayed as they arrive (>= 2)", len(chunks))
	}
	if joined := strings.Join(chunks, ""); joined != strings.Join(events, "") {
		t.Fatalf("relayed body = %q, want %q", joined, strings.Join(events, ""))
	}
}

// TestChannelConnectionReuse is the unit twin of harness scenario 13: N requests
// for the same (provider, host) must ride exactly ONE upstream TCP connection.
func TestChannelConnectionReuse(t *testing.T) {
	srv, conns := newConnCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	cm := newTestManager(t)
	for i := 0; i < 5; i++ {
		_, err := cm.Do(context.Background(),
			testReq(tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/x", Body: []byte("{}")}),
			func([]byte) error { return nil })
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}
	if n := conns.Load(); n != 1 {
		t.Errorf("server saw %d connections, want 1 (resident session reused)", n)
	}
}

// TestChannelProviderIsolation asserts that two providers hitting the SAME host
// do not share a connection: each provider owns its own resident pool, so the
// upstream's source IP stays pinned to the provider whose credential is spent.
func TestChannelProviderIsolation(t *testing.T) {
	srv, conns := newConnCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	reg := NewRegistry()
	reg.Set("a", Endpoint{})
	reg.Set("b", Endpoint{})
	cm, err := NewChannelManager(ChannelConfig{
		Scheme:         "http",
		AllowPlaintext: true,
		Endpoints:      reg,
	})
	if err != nil {
		t.Fatalf("NewChannelManager: %v", err)
	}
	defer func() { _ = cm.Close() }()

	host := hostOf(srv)
	for i := 0; i < 3; i++ {
		for _, provider := range []string{"a", "b"} {
			_, err := cm.Do(context.Background(),
				tee.Request{Method: "POST", Provider: provider, Host: host, Path: "/v1/x", Body: []byte("{}")},
				func([]byte) error { return nil })
			if err != nil {
				t.Fatalf("provider %q request %d: %v", provider, i+1, err)
			}
		}
	}
	if n := conns.Load(); n != 2 {
		t.Errorf("server saw %d connections, want 2 (one per provider, never shared)", n)
	}
}

// TestChannelDeadConnectionReDialsOnce covers the wroteNothing rule: a pooled
// connection that died costs nothing, so when zero bytes left the TEE the same
// request is re-dialed exactly once instead of failing.
func TestChannelDeadConnectionReDialsOnce(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var accepted atomic.Int32
	conn1 := make(chan net.Conn, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			if accepted.Load() == 1 {
				conn1 <- conn // hand the first accepted socket to the test for resetting
			}
			go serveRawConn(conn)
		}
	}()

	reg := NewRegistry()
	reg.Set("p", Endpoint{})
	cm, err := NewChannelManager(ChannelConfig{
		Scheme:         "http",
		AllowPlaintext: true,
		Endpoints:      reg,
	})
	if err != nil {
		t.Fatalf("NewChannelManager: %v", err)
	}
	defer func() { _ = cm.Close() }()

	host := ln.Addr().String()
	req := func() error {
		_, err := cm.Do(context.Background(),
			testReq(tee.Request{Method: "GET", Host: host, Path: "/v1/x"}),
			func([]byte) error { return nil })
		return err
	}

	// Request 1 dials connection 1 and pools it.
	if err := req(); err != nil {
		t.Fatalf("request 1: %v", err)
	}

	// Now pull connection 1 out from under the pool and reset it with an RST so
	// the client's next write reports zero bytes (a graceful FIN would let the
	// write succeed and only the read fail, which is not the wroteNothing case).
	first := <-conn1
	if tc, ok := first.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = first.Close()
	time.Sleep(100 * time.Millisecond) // let the RST reach the client socket

	// Request 2 reuses the dead pooled connection, writes nothing, re-dials.
	if err := req(); err != nil {
		t.Fatalf("request 2 (re-dial expected): %v", err)
	}
	if n := accepted.Load(); n != 2 {
		t.Errorf("server accepted %d connections, want 2 (1 original + 1 re-dial)", n)
	}
}

// serveRawConn answers HTTP/1.1 keep-alive requests with a tiny fixed body.
func serveRawConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
		}
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nok")
	}
}

func TestChannelIdleConnectionsAreReaped(t *testing.T) {
	// A server that records both new connections and connection closes, so the
	// test can observe the socket going away while it is merely idle — the
	// property only the background sweeper provides.
	var newConns, closes atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
		if state == http.StateClosed || state == http.StateHijacked {
			closes.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	reg := NewRegistry()
	reg.Set("p", Endpoint{})
	cm, err := NewChannelManager(ChannelConfig{
		Scheme:         "http",
		AllowPlaintext: true,
		Endpoints:      reg,
		IdleTimeout:    150 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewChannelManager: %v", err)
	}
	defer func() { _ = cm.Close() }()

	do := func() error {
		_, err := cm.Do(context.Background(),
			testReq(tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/x", Body: []byte("{}")}),
			func([]byte) error { return nil })
		return err
	}

	if err := do(); err != nil {
		t.Fatalf("request 1: %v", err)
	}
	if n := newConns.Load(); n != 1 {
		t.Fatalf("after request 1: server saw %d new connections, want 1", n)
	}

	// Wait for the background sweeper to close the now-idle connection, without
	// sending another request. A manager that only reaps lazily on the next
	// acquisition would leave this socket open forever.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if closes.Load() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if closes.Load() == 0 {
		t.Fatal("idle connection was never closed by the background sweeper")
	}

	if err := do(); err != nil {
		t.Fatalf("request 2: %v", err)
	}
	if n := newConns.Load(); n != 2 {
		t.Errorf("after re-dial: server saw %d new connections, want 2 (a fresh dial after the reap)", n)
	}
}

func TestChannelMidStreamDisconnect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		fmt.Fprint(w, "data: one\n\n")
		flusher.Flush()
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
	}))
	defer srv.Close()

	cm := newTestManager(t)
	var chunks int
	_, err := cm.Do(context.Background(),
		testReq(tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/x", Body: []byte("{}")}),
		func([]byte) error {
			chunks++
			return nil
		})
	if err == nil {
		t.Fatal("mid-stream disconnect returned nil error; the receipt would attest a whole transcript")
	}
	if chunks == 0 {
		t.Error("no chunks relayed before the disconnect")
	}
}

func TestChannelOnChunkErrorStopsRelay(t *testing.T) {
	sentinel := errors.New("consumer went away")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for i := 0; i < 5; i++ {
			fmt.Fprintf(w, "data: event-%d\n\n", i)
			flusher.Flush()
		}
	}))
	defer srv.Close()

	cm := newTestManager(t)
	var delivered atomic.Int32
	_, err := cm.Do(context.Background(),
		testReq(tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/x", Body: []byte("{}")}),
		func([]byte) error {
			delivered.Add(1)
			return sentinel
		})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the consumer sentinel", err)
	}
	if delivered.Load() != 1 {
		t.Errorf("consumer invoked %d times after aborting, want 1", delivered.Load())
	}
}

func TestChannelTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	cm := newTestManager(t)
	start := time.Now()
	_, err := cm.Do(context.Background(),
		testReq(tee.Request{Method: "GET", Host: hostOf(srv), Path: "/slow", Timeout: 50 * time.Millisecond}),
		func([]byte) error { return nil })
	if err == nil {
		t.Fatal("timeout produced nil error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("timeout took %v to fire", elapsed)
	}
}

func TestChannelErrorStatusSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "quota exceeded", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	cm := newTestManager(t)
	resp, err := cm.Do(context.Background(),
		testReq(tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/x", Body: []byte("{}")}),
		func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("Do: %v (an HTTP error status is an answer, not a transport failure)", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}
}

func TestChannelRedirectSurfacedNotFollowed(t *testing.T) {
	var followed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(http.StatusFound)
			return
		}
		followed.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cm := newTestManager(t)
	resp, err := cm.Do(context.Background(),
		testReq(tee.Request{Method: "GET", Host: hostOf(srv), Path: "/start"}),
		func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d (redirect surfaced, not followed)", resp.StatusCode, http.StatusFound)
	}
	if followed.Load() {
		t.Error("transport followed the redirect; the credential would have been re-sent elsewhere")
	}
}

func TestChannelCompressedBodyPassesThroughVerbatim(t *testing.T) {
	payload := bytes.Repeat([]byte("TokenHive transcript must survive verbatim. "), 8)
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	var sawAcceptEncoding atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAcceptEncoding.Store(r.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(compressed.Bytes())
	}))
	defer srv.Close()

	cm := newTestManager(t)
	var received bytes.Buffer
	_, err := cm.Do(context.Background(),
		testReq(tee.Request{Method: "GET", Host: hostOf(srv), Path: "/v1/models"}),
		func(chunk []byte) error {
			received.Write(chunk)
			return nil
		})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	// The hand-serialised request adds no Accept-Encoding, and http.ReadResponse
	// does not decompress, so a provider-caused gzip body arrives verbatim.
	if got, _ := sawAcceptEncoding.Load().(string); got != "" {
		t.Errorf("transport injected Accept-Encoding: %q", got)
	}
	if !bytes.Equal(received.Bytes(), compressed.Bytes()) {
		t.Error("response was decompressed in transit; the attested transcript diverges from the wire")
	}
}

func TestChannelUnknownEndpoint(t *testing.T) {
	reg := NewRegistry()
	cm, err := NewChannelManager(ChannelConfig{
		Scheme:         "http",
		AllowPlaintext: true,
		Endpoints:      reg,
	})
	if err != nil {
		t.Fatalf("NewChannelManager: %v", err)
	}
	defer func() { _ = cm.Close() }()

	_, err = cm.Do(context.Background(),
		tee.Request{Method: "GET", Provider: "nobody", Host: "127.0.0.1:1", Path: "/v1/x"},
		func([]byte) error { return nil })
	if !errors.Is(err, ErrUnknownEndpoint) {
		t.Fatalf("error = %v, want ErrUnknownEndpoint", err)
	}
}

func TestChannelSchemeValidation(t *testing.T) {
	reg := NewRegistry()
	if _, err := NewChannelManager(ChannelConfig{Scheme: "ftp", Endpoints: reg}); !errors.Is(err, ErrUnsupportedScheme) {
		t.Fatalf("error = %v, want ErrUnsupportedScheme", err)
	}
	if _, err := NewChannelManager(ChannelConfig{Scheme: "http", Endpoints: reg}); !errors.Is(err, ErrPlaintextNotAllowed) {
		t.Fatalf("error = %v, want ErrPlaintextNotAllowed", err)
	}
}

func TestChannelNoRegistry(t *testing.T) {
	if _, err := NewChannelManager(ChannelConfig{Scheme: "https"}); err == nil {
		t.Fatal("expected an error for a missing endpoint registry")
	}
}

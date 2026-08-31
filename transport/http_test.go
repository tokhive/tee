package transport

import (
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

func newLocalTransport(t *testing.T) *HTTP {
	t.Helper()
	tr, err := New(Config{Scheme: "http", AllowPlaintext: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return tr
}

func TestBasicExchange(t *testing.T) {
	var got struct {
		method string
		path   string
		query  string
		header string
		auth   string
		body   string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("server read body: %v", err)
		}
		got.method = r.Method
		got.path = r.URL.Path
		got.query = r.URL.RawQuery
		got.header = r.Header.Get("X-Custom")
		got.auth = r.Header.Get("Authorization")
		got.body = string(body)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hello world")
	}))
	defer srv.Close()

	tr := newLocalTransport(t)
	var chunks []string
	resp, err := tr.Do(context.Background(),
		tee.Request{
			Method:  "POST",
			Host:    hostOf(srv),
			Path:    "/v1/chat/completions",
			Query:   "model=glm-5&stream=true",
			Headers: map[string]string{"X-Custom": "value", "Authorization": "Bearer secret-token"},
			Body:    []byte(`{"messages":[]}`),
		},
		func(chunk []byte) error {
			chunks = append(chunks, string(chunk))
			return nil
		})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
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

func TestSSEStreamRelayed(t *testing.T) {
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

	tr := newLocalTransport(t)
	var chunks []string
	_, err := tr.Do(context.Background(),
		tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/chat/completions", Body: []byte("{}")},
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

func TestConnectionReuse(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	var conns atomic.Int32
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	tr := newLocalTransport(t)
	for i := 0; i < 3; i++ {
		_, err := tr.Do(context.Background(),
			tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/x", Body: []byte("{}")},
			func([]byte) error { return nil })
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}
	if n := conns.Load(); n != 1 {
		t.Errorf("server saw %d connections, want 1 (keep-alive reuse)", n)
	}
}

func TestRedirectSurfacedNotFollowed(t *testing.T) {
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

	tr := newLocalTransport(t)
	resp, err := tr.Do(context.Background(),
		tee.Request{Method: "GET", Host: hostOf(srv), Path: "/start"},
		func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d (redirect surfaced, not followed)", resp.StatusCode, http.StatusFound)
	}
	if followed.Load() {
		t.Error("client followed the redirect; the credential would have been re-sent")
	}
}

func TestOnChunkErrorStopsRelay(t *testing.T) {
	sentinel := errors.New("consumer went away")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for i := 0; i < 5; i++ {
			fmt.Fprintf(w, "data: event-%d\n\n", i)
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer srv.Close()

	tr := newLocalTransport(t)
	var delivered atomic.Int32
	_, err := tr.Do(context.Background(),
		tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/x", Body: []byte("{}")},
		func([]byte) error {
			delivered.Add(1)
			return sentinel
		})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the consumer sentinel", err)
	}
	if n := delivered.Load(); n != 1 {
		t.Errorf("consumer invoked %d times after aborting, want 1", n)
	}
}

func TestMidStreamDisconnect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		fmt.Fprint(w, "data: one\n\n")
		flusher.Flush()
		// Drop the connection with the transcript unfinished: no terminal
		// chunk marker, no EOF. The transport must report the failure rather
		// than hand back a silent success.
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()

	tr := newLocalTransport(t)
	var chunks int
	_, err := tr.Do(context.Background(),
		tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/x", Body: []byte("{}")},
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

func TestCompressedBodyPassesThroughVerbatim(t *testing.T) {
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

	tr := newLocalTransport(t)
	var received bytes.Buffer
	_, err := tr.Do(context.Background(),
		tee.Request{Method: "GET", Host: hostOf(srv), Path: "/v1/models"},
		func(chunk []byte) error {
			received.Write(chunk)
			return nil
		})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := sawAcceptEncoding.Load().(string); got != "" {
		t.Errorf("transport injected Accept-Encoding: %q; the digest would no longer describe the provider's own encoding", got)
	}
	if !bytes.Equal(received.Bytes(), compressed.Bytes()) {
		t.Error("response was decompressed in transit; the attested transcript diverges from the wire")
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Park until the client gives up so the handler never outlives the test.
		<-r.Context().Done()
	}))
	defer srv.Close()

	tr := newLocalTransport(t)
	start := time.Now()
	_, err := tr.Do(context.Background(),
		tee.Request{Method: "GET", Host: hostOf(srv), Path: "/slow", Timeout: 50 * time.Millisecond},
		func([]byte) error { return nil })
	if err == nil {
		t.Fatal("timeout produced nil error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("timeout took %v to fire", elapsed)
	}
}

func TestErrorStatusSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "quota exceeded", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	tr := newLocalTransport(t)
	resp, err := tr.Do(context.Background(),
		tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/x", Body: []byte("{}")},
		func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("Do: %v (an HTTP error status is an answer, not a transport failure)", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}
}

func TestDialContextUsed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	var dials atomic.Int32
	tr, err := New(Config{
		Scheme:         "http",
		AllowPlaintext: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = tr.Do(context.Background(),
		tee.Request{Method: "GET", Host: hostOf(srv), Path: "/v1/models"},
		func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if dials.Load() != 1 {
		t.Errorf("custom dialer invoked %d times, want 1", dials.Load())
	}
}

func TestSchemeValidation(t *testing.T) {
	_, err := New(Config{Scheme: "ftp"})
	if !errors.Is(err, ErrUnsupportedScheme) {
		t.Fatalf("error = %v, want ErrUnsupportedScheme", err)
	}
}

func TestRequestNotReplayable(t *testing.T) {
	cases := []struct {
		method string
		body   []byte
	}{
		{method: "GET", body: nil},
		{method: "POST", body: []byte(`{"m":1}`)},
	}
	for _, tc := range cases {
		out, err := buildRequest(context.Background(), "https",
			tee.Request{Method: tc.method, Host: "api.example.com", Path: "/v1/x", Body: tc.body})
		if err != nil {
			t.Fatalf("%s: buildRequest: %v", tc.method, err)
		}
		// A non-nil body without GetBody is what makes the standard library
		// treat a request as non-replayable; a nil body (or one with GetBody)
		// reopens the silent-retry window the tee contract forbids.
		if out.Body == nil {
			t.Errorf("%s: nil body — the request is replayable and may be silently retried", tc.method)
		}
		if out.GetBody != nil {
			t.Errorf("%s: GetBody set — the request is replayable and may be silently retried", tc.method)
		}
		if want := int64(len(tc.body)); out.ContentLength != want {
			t.Errorf("%s: ContentLength = %d, want %d", tc.method, out.ContentLength, want)
		}
	}
}

func TestEscapedPathAndQueryPreserved(t *testing.T) {
	var requestURI atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURI.Store(r.RequestURI)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := newLocalTransport(t)
	_, err := tr.Do(context.Background(),
		tee.Request{
			Method: "GET",
			Host:   hostOf(srv),
			Path:   "/v1/models%2Fdetail",
			Query:  "filter=a%20b&next=1",
		},
		func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	got, _ := requestURI.Load().(string)
	want := "/v1/models%2Fdetail?filter=a%20b&next=1"
	if got != want {
		t.Errorf("RequestURI = %q, want %q (escaping must be preserved verbatim)", got, want)
	}
}

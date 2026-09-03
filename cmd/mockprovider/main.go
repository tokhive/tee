// Command mockprovider is a stand-in for an LLM provider. It serves three
// wire shapes — OpenAI chat completions, Anthropic messages, and OpenAI
// Responses — all returning FIXED SSE streams and never invoking a real model.
// It exists purely so the simulation has something to talk to over real TLS.
//
// Fault injection (query param ?fault=...):
//
//	401       -> reject with 401 Unauthorized
//	429       -> reject with 429 Too Many Requests
//	truncate  -> send the first chunk, then hard-close the TCP connection
//	empty     -> 200 with an empty body (zero chunks)
//	big       -> stream ~3 MiB fast, for MaxResponseBytes truncation tests
//	slow      -> hold the connection open, for agent-kill tests
//
// /stats reports how many distinct TCP connections the upstream has seen. It
// exists to make the TEE's connection-resident guarantee observable: N requests
// that reuse one resident TLS session show up as 1 new connection; a fresh
// dial is the only thing that increments it.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
)

// connStats tallies TCP connections seen by the HTTP server. newConns is
// incremented exactly once per distinct socket (http.StateNew of ConnState):
// an idle, kept-alive connection serving a later request transitions
// StateIdle -> StateActive and never touches StateNew again, so newConns is the
// number of sockets the upstream saw, not the number of requests.
var connStats struct {
	mu       sync.Mutex
	newConns int64
	active   int64
	maxConns int64
}

// statsResponse is the JSON served at /stats.
type statsResponse struct {
	NewConns int64 `json:"new_conns"`
	Active   int64 `json:"active"`
	MaxConns int64 `json:"max_conns"`
}

// trackConn is the http.Server.ConnState callback that drives the counters.
func trackConn(_ net.Conn, s http.ConnState) {
	connStats.mu.Lock()
	defer connStats.mu.Unlock()
	switch s {
	case http.StateNew:
		connStats.newConns++
		connStats.active++
		if connStats.active > connStats.maxConns {
			connStats.maxConns = connStats.active
		}
	case http.StateClosed, http.StateHijacked:
		if connStats.active > 0 {
			connStats.active--
		}
	}
}

// handleStats reports the cumulative connection counters.
func handleStats(w http.ResponseWriter, _ *http.Request) {
	connStats.mu.Lock()
	resp := statsResponse{
		NewConns: connStats.newConns,
		Active:   connStats.active,
		MaxConns: connStats.maxConns,
	}
	connStats.mu.Unlock()
	_ = json.NewEncoder(w).Encode(resp)
}

// handleReset zeroes the counters. The harness uses it to give scenario 13 a
// clean baseline before asserting "exactly one connection".
func handleReset(w http.ResponseWriter, _ *http.Request) {
	connStats.mu.Lock()
	connStats.newConns = 0
	connStats.active = 0
	connStats.maxConns = 0
	connStats.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// chatChunks is the fixed, deterministic OpenAI chat-completions stream.
// Because it never changes, the TEE's StreamHash is stable and the Hub can
// make golden assertions against it.
var chatChunks = []string{
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{"role":"assistant","content":"你好"}}]}`,
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{"content":"，我是由 TokenHive 托管的"}}]}`,
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{"content":"模拟模型，不调用任何真实大模型。"}}]}`,
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{},"finish_reason":"stop"}]}`,
}

// responsesChunks is the fixed, deterministic OpenAI Responses stream. Each
// element is one SSE event's data payload (the wire carries `data: <json>`);
// the terminal response.completed event is what an SDK treats as the end of
// the stream, so no extra [DONE] is needed.
var responsesChunks = []string{
	`{"type":"response.created","response":{"id":"resp_sim1","object":"response","status":"in_progress","model":"sim-mock-0.5b"}}`,
	`{"type":"response.output_text.delta","delta":"你好，我是由 TokenHive 托管的"}`,
	`{"type":"response.output_text.delta","delta":"模拟模型，不调用任何真实大模型。"}`,
	`{"type":"response.completed","response":{"id":"resp_sim1","object":"response","status":"completed"}}`,
}

// anthropicMessagesChunks is the fixed, deterministic Anthropic Messages
// stream. Anthropic SSE frames carry an event: name and a data: payload; the
// terminal message_stop event ends the stream, so no extra [DONE] is needed.
var anthropicMessagesChunks = [][2]string{
	{"message_start", `{"type":"message_start","message":{"id":"msg_sim1","type":"message","role":"assistant","model":"sim-claude-haiku","content":[]}}`},
	{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"你好，我是由 TokenHive 托管的模拟 Claude 模型。"}}`},
	{"message_stop", `{"type":"message_stop"}`},
}

// sseFrame renders one OpenAI-style SSE event: `data: <payload>\n\n`.
func sseFrame(payload string) string { return "data: " + payload + "\n\n" }

// anthropicFrame renders one Anthropic SSE event: `event: <name>\ndata: <payload>\n\n`.
func anthropicFrame(name, payload string) string {
	return "event: " + name + "\ndata: " + payload + "\n\n"
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18080", "listen address")
	useTLS := flag.Bool("tls", true, "serve over HTTPS using a generated test CA")
	statsAddr := flag.String("stats-addr", "127.0.0.1:18081", "plain-HTTP listener for /stats and /reset")
	flag.Parse()

	// The provider's one HTTP server, whose connections are the thing being
	// counted. /v1/chat/completions, /v1/messages, and /v1/responses are the
	// fixed SSE endpoints the Hub's user API relays; /v1/realtime is the
	// streaming-session (WebSocket) endpoint scenario 14 exercises.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", handleChat)
	mux.HandleFunc("/v1/messages", handleMessages)
	mux.HandleFunc("/v1/responses", handleResponses)
	mux.HandleFunc("/v1/realtime", handleRealtime)
	srv := &http.Server{Addr: *addr, Handler: mux, ConnState: trackConn}

	// A separate, untracked listener for the observability endpoints. Reading
	// /stats here never perturbs new_conns, so the harness can assert "exactly
	// one upstream connection" without its own probe skewing the answer.
	statsMux := http.NewServeMux()
	statsMux.HandleFunc("/stats", handleStats)
	statsMux.HandleFunc("/reset", handleReset)
	statsSrv := &http.Server{Addr: *statsAddr, Handler: statsMux}
	go func() {
		log.Printf("mockprovider stats (plain HTTP) listening on http://%s", *statsAddr)
		log.Fatal(statsSrv.ListenAndServe())
	}()

	if *useTLS {
		if err := shared.EnsureDefaults(); err != nil {
			log.Fatalf("ensure defaults: %v", err)
		}
		cfg, caPEM, err := shared.GenCerts()
		if err != nil {
			log.Fatalf("gen certs: %v", err)
		}
		if err := os.WriteFile(shared.CAPEMPath(), caPEM, 0o644); err != nil {
			log.Fatalf("write CA: %v", err)
		}
		srv.TLSConfig = cfg
		log.Printf("mockprovider (TLS) listening on https://%s", *addr)
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}

	log.Printf("mockprovider (plain HTTP) listening on http://%s", *addr)
	log.Fatal(srv.ListenAndServe())
}

// streamHandler writes one fixed SSE body, applying the fault switch. frames
// are the fully-rendered SSE events; emit may be nil.
type streamHandler struct {
	// fault is the ?fault= query value; empty means the normal fixed stream.
	fault string
	// frames returns the wire frames to stream on the normal path.
	frames func() []string
}

func (h streamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch h.fault {
	case "401":
		http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
		return
	case "429":
		http.Error(w, `{"error":"rate limited"}`, http.StatusTooManyRequests)
		return
	case "empty":
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		return
	case "slow":
		// Hold the connection open past the first byte so a test can kill the
		// egress agent mid-request and confirm the TEE/hub fail cleanly.
		time.Sleep(2 * time.Second)
	case "big":
		// Stream far more than any sane cap so the TEE exercises its
		// MaxResponseBytes enforcement over a real provider connection.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		chunk := strings.Repeat("x", 1<<16) // 64 KiB per chunk
		for i := 0; i < 48; i++ {           // ~3 MiB total, over the 1 MiB cap
			fmt.Fprintf(w, "data: %s\n\n", chunk)
			if flusher != nil {
				flusher.Flush()
			}
		}
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	frames := h.frames()
	for i, frame := range frames {
		if h.fault == "truncate" && i >= 1 {
			// Send one frame, then violently close the connection to simulate
			// the provider dropping mid-stream.
			if hijacker, ok := w.(http.Hijacker); ok {
				if conn, _, herr := hijacker.Hijack(); herr == nil {
					_ = conn.Close()
					return
				}
			}
		}
		fmt.Fprint(w, frame)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	handler := streamHandler{fault: r.URL.Query().Get("fault")}
	handler.frames = func() []string {
		frames := make([]string, 0, len(chatChunks))
		for _, chunk := range chatChunks {
			frames = append(frames, sseFrame(chunk))
		}
		return frames
	}
	handler.ServeHTTP(w, r)
}

func handleMessages(w http.ResponseWriter, r *http.Request) {
	handler := streamHandler{fault: r.URL.Query().Get("fault")}
	handler.frames = func() []string {
		frames := make([]string, 0, len(anthropicMessagesChunks))
		for _, pair := range anthropicMessagesChunks {
			frames = append(frames, anthropicFrame(pair[0], pair[1]))
		}
		return frames
	}
	handler.ServeHTTP(w, r)
}

func handleResponses(w http.ResponseWriter, r *http.Request) {
	handler := streamHandler{fault: r.URL.Query().Get("fault")}
	handler.frames = func() []string {
		frames := make([]string, 0, len(responsesChunks))
		for _, chunk := range responsesChunks {
			frames = append(frames, sseFrame(chunk))
		}
		return frames
	}
	handler.ServeHTTP(w, r)
}

// realtimeUpgrader turns /v1/realtime into a WebSocket for streaming sessions.
// Origin is unrestricted — the "client" here is an opaque provider tunnel, not
// a browser, so there is no Origin to police.
var realtimeUpgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

// realtimeFrames is the fixed, deterministic frame sequence a session produces.
// The first element is echoed back to the client's uplink marker, so scenario 14
// can prove the full-duplex byte relay works in both directions and that the
// session receipt digests exactly these bytes.
func realtimeFrames(echo string) []string {
	return []string{
		`{"event":"session.updated","seq":1,"echo":` + jsonString(echo) + `}`,
		`{"event":"response.created","seq":2,"echo":` + jsonString(echo) + `}`,
		`{"event":"response.done","seq":3,"echo":` + jsonString(echo) + `}`,
	}
}

// handleRealtime serves one streaming session: it reads a single client text
// message (the uplink marker), replies with the fixed frame sequence, then
// closes the WebSocket normally. Frame order is fixed so the Hub-side driver can
// assert it, and the echoed marker proves the uplink reached the provider.
func handleRealtime(w http.ResponseWriter, r *http.Request) {
	conn, err := realtimeUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	echo := "realtime"
	// Uplink direction: the relay wrote one masked client text frame; read it to
	// echo. We are permissive — if it fails we still stream the fixed frames.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, data, rerr := conn.ReadMessage(); rerr == nil {
		if s := strings.TrimSpace(string(data)); s != "" {
			echo = s
		}
	}
	conn.SetReadDeadline(time.Time{})

	for _, frame := range realtimeFrames(echo) {
		if werr := conn.WriteMessage(websocket.TextMessage, []byte(frame)); werr != nil {
			return
		}
	}
	_ = conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"))
}

// jsonString renders a string as a JSON string literal, safe for embedding in a
// frame. The echo markers the simulation uses are plain, but escaping here keeps
// the endpoint honest for any payload.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

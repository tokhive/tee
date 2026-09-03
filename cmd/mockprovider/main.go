// Command mockprovider is a stand-in for an LLM provider (OpenAI-compatible
// chat completions endpoint). It returns a FIXED set of SSE chunks and never
// invokes a real model. It exists purely so the simulation has something to
// talk to over real TLS.
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

// mockChunks is the fixed, deterministic response stream. Because it never
// changes, the TEE's StreamHash is stable and the Hub can make golden
// assertions against it.
var mockChunks = []string{
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{"role":"assistant","content":"你好"}}]}`,
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{"content":"，我是由 TokenHive 托管的"}}]}`,
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{"content":"模拟模型，不调用任何真实大模型。"}}]}`,
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{},"finish_reason":"stop"}]}`,
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18080", "listen address")
	useTLS := flag.Bool("tls", true, "serve over HTTPS using a generated test CA")
	statsAddr := flag.String("stats-addr", "127.0.0.1:18081", "plain-HTTP listener for /stats and /reset")
	flag.Parse()

	// The provider's one HTTP server, whose connections are the thing being
	// counted. Only /v1/chat/completions lives here: a stats query dials a
	// connection too, so it must share the counter with neither the count it
	// reports nor the message traffic it observes.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", handleChat)
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

func handleChat(w http.ResponseWriter, r *http.Request) {
	fault := r.URL.Query().Get("fault")
	switch fault {
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

	for i, chunk := range mockChunks {
		if fault == "truncate" && i >= 1 {
			// Send one chunk, then violently close the connection to simulate
			// the provider dropping mid-stream.
			if hijacker, ok := w.(http.Hijacker); ok {
				if conn, _, herr := hijacker.Hijack(); herr == nil {
					_ = conn.Close()
					return
				}
			}
		}
		fmt.Fprintf(w, "data: %s\n\n", chunk)
		if flusher != nil {
			flusher.Flush()
		}
	}
}
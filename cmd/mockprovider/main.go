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
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
)

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
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", handleChat)

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
		srv := &http.Server{Addr: *addr, Handler: mux, TLSConfig: cfg}
		log.Printf("mockprovider (TLS) listening on https://%s", *addr)
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}

	log.Printf("mockprovider (plain HTTP) listening on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
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

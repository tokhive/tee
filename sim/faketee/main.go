// Command faketee is the simulated TEE. It implements the single RPC from the
// final plan: POST /v1/execute (canonical-CBOR ExecuteRequest) -> SSE stream
// of response chunks, terminated by an `event: receipt` frame carrying a
// base64 SignedReceipt.
//
// It does exactly the byte-layer work a real TEE would:
//   - enforce the per-provider Policy whitelist (host/path/method, https-only)
//   - inject the provider credential the Hub never sees
//   - open a real TLS connection to the provider
//   - stream the response back, hashing it for the receipt
//   - sign a receipt binding RequestBytes and a monotonic ProviderSeq
//
// The only thing that is "simulated" is the attestation root: it uses
// platform/simulated instead of a real SEV-SNP enclave. proof.Signer and
// proof.Verify run unchanged.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/sim/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/sim/seqstore"
)

type server struct {
	epoch platform.Epoch
	store seqstore.SeqStore
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18090", "listen address")
	seqPath := flag.String("seq", filepath.Join(shared.ConfigDir(), "seqstore.json"), "ProviderSeq store file")
	flag.Parse()

	if err := shared.EnsureDefaults(); err != nil {
		log.Fatalf("ensure defaults: %v", err)
	}

	epoch, err := simulated.NewEpoch()
	if err != nil {
		log.Fatalf("create sim epoch: %v", err)
	}
	if err := shared.WriteTEEIdentity(epoch.Identity()); err != nil {
		log.Fatalf("write tee identity: %v", err)
	}
	store, err := seqstore.NewFileStore(*seqPath)
	if err != nil {
		log.Fatalf("open seqstore: %v", err)
	}

	srv := &server{epoch: epoch, store: store}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/execute", srv.handleExecute)
	log.Printf("faketee (sim TEE) listening on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func (s *server) handleExecute(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	req, err := shared.DecodeExecuteRequest(raw)
	if err != nil {
		http.Error(w, "decode request: "+err.Error(), http.StatusBadRequest)
		return
	}
	spec := req.Spec
	if err := spec.ValidateAt(time.Now()); err != nil {
		http.Error(w, "invalid spec: "+err.Error(), http.StatusBadRequest)
		return
	}

	// --- TEE authorization: enforce the whitelist before touching a credential.
	policy, err := shared.LoadPolicy()
	if err != nil {
		http.Error(w, "load policy: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rule, ok := policy[spec.Provider]
	if !ok {
		http.Error(w, "unknown provider", http.StatusForbidden)
		return
	}
	if err := shared.CheckPolicy(rule, spec); err != nil {
		// Refusal: no receipt is emitted. The Hub learns nothing about the
		// credential and cannot retry against a different target.
		http.Error(w, "policy denied: "+err.Error(), http.StatusForbidden)
		return
	}

	providers, err := shared.LoadProviders()
	if err != nil {
		http.Error(w, "load providers: "+err.Error(), http.StatusInternalServerError)
		return
	}
	token, ok := providers[spec.Provider]
	if !ok {
		http.Error(w, "no credential for provider", http.StatusForbidden)
		return
	}

	seq, err := s.store.Next([]byte(spec.Provider))
	if err != nil {
		http.Error(w, "seqstore: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// --- Open a real TLS connection to the provider, injecting the credential.
	target := "https://" + spec.Host + spec.Path
	if spec.Query != "" {
		target += "?" + spec.Query
	}
	outReq, err := http.NewRequest(spec.Method, target, bytes.NewReader(req.Body))
	if err != nil {
		http.Error(w, "build request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	for k, v := range spec.Headers {
		outReq.Header.Set(k, v)
	}
	outReq.Header.Set("Authorization", "Bearer "+token) // the secret the Hub never sees
	outReq.Header.Set("Content-Type", "application/json")
	outReq.Header.Set("Accept", "text/event-stream")

	caPool, err := shared.LoadCAPool()
	if err != nil {
		http.Error(w, "load CA: "+err.Error(), http.StatusInternalServerError)
		return
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12},
	}}

	started := time.Now()
	reqBodyLen := uint64(len(req.Body))
	resp, err := client.Do(outReq)
	if err != nil {
		s.writeReceipt(w, spec, seq, uint32(http.StatusBadGateway), nil, proof.CompletionFailed, started, time.Now(), reqBodyLen, "provider unreachable: "+err.Error())
		return
	}
	statusCode := resp.StatusCode

	// --- Stream the response back, hashing it for the receipt.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	hasher := proof.NewStreamingHasher(spec.JobID)
	reader := bufio.NewReader(resp.Body)
	completion := proof.CompletionComplete

	if statusCode != http.StatusOK {
		fmt.Fprintf(w, "event: error\ndata: provider returned %d\n\n", statusCode)
		if flusher != nil {
			flusher.Flush()
		}
		completion = proof.CompletionFailed
	}

	for {
		line, rerr := reader.ReadString('\n')
		trimmed := strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(trimmed, "data:") {
			payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
			if payload != "" && payload != "[DONE]" {
				_ = hasher.WriteChunk([]byte(payload))
				fmt.Fprintf(w, "data: %s\n\n", payload)
				if flusher != nil {
					flusher.Flush()
				}
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				// Connection dropped mid-stream: the response is truncated.
				completion = proof.CompletionTruncated
			}
			break
		}
	}
	_ = resp.Body.Close()
	finished := time.Now()

	s.writeReceipt(w, spec, seq, uint32(statusCode), hasher, completion, started, finished, reqBodyLen, "")
}

func (s *server) writeReceipt(w http.ResponseWriter, spec jobs.Spec, seq uint64, status uint32, hasher *proof.StreamingHasher, completion proof.CompletionState, started, finished time.Time, reqBodyLen uint64, errMsg string) {
	if errMsg != "" {
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", errMsg)
	}
	if hasher == nil {
		hasher = proof.NewStreamingHasher(spec.JobID)
	}

	policy, _ := shared.LoadPolicy()
	rule, _ := policy[spec.Provider]
	ruleBytes, _ := json.Marshal(rule)
	ph := sha256.Sum256(append([]byte("TokenHive.ProviderPolicy.v1"), ruleBytes...))

	sum := hasher.Sum()
	receipt := proof.Receipt{
		Version:       proof.VersionV1,
		JobID:         spec.JobID,
		JobSpecHash:   mustHash(spec),
		Provider:      spec.Provider,
		Method:        spec.Method,
		Host:          spec.Host,
		Path:          spec.Path,
		StatusCode:    status,
		StreamHash:    sum[:],
		ChunkCount:    hasher.ChunkCount(),
		ResponseBytes: hasher.BytesWritten(),
		Completion:    completion,
		StartedAt:     started.Unix(),
		FinishedAt:    finished.Unix(),
		PolicyHash:    ph[:],
		RequestBytes:  reqBodyLen,
		ProviderSeq:   seq,
	}
	signAndEmit(w, s.epoch, receipt)
}

func mustHash(spec jobs.Spec) []byte {
	h, err := spec.Hash()
	if err != nil {
		panic(err)
	}
	return h[:]
}

func signAndEmit(w http.ResponseWriter, epoch platform.Epoch, receipt proof.Receipt) {
	// sim-only convenience: keep each receipt self-contained so the offline
	// verifier needs no external attestation cache. Production keeps this
	// false and resolves EvidenceHash from its own trust store (see plan P0).
	signer := proof.NewSigner(epoch)
	signer.IncludeEvidence = true
	signed, err := signer.Sign(receipt)
	if err != nil {
		log.Printf("sign receipt: %v", err)
		return
	}
	enc, err := signed.EncodeCanonical()
	if err != nil {
		log.Printf("encode receipt: %v", err)
		return
	}
	flusher, _ := w.(http.Flusher)
	fmt.Fprintf(w, "event: receipt\ndata: %s\n\n", base64.StdEncoding.EncodeToString(enc))
	if flusher != nil {
		flusher.Flush()
	}
}

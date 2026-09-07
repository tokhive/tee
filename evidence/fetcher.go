package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// HTTPStore is the server half of evidence retrieval: it serves the Store's
// contents over HTTP so a verifier on another host can resolve a hash-only
// receipt against evidence the TEE published. It exposes two routes:
//
//	GET /v1/evidence/<hex-hash>   raw evidence bytes for that hash (200) or 404
//	GET /v1/evidence              JSON list of stored hex hashes (for syncing)
//
// A Hub or auditor wires an evidence.HTTPFetcher at this base URL.
type HTTPServer struct {
	Store *Store
}

// NewHTTPServer returns a handler serving the given store.
func NewHTTPServer(store *Store, mux *http.ServeMux) *HTTPServer {
	if mux == nil {
		mux = http.NewServeMux()
	}
	h := &HTTPServer{Store: store}
	mux.HandleFunc("/v1/evidence", h.handleList)
	mux.HandleFunc("/v1/evidence/", h.handleGet)
	return h
}

func (h *HTTPServer) handleList(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/evidence" {
		h.handleGet(w, r)
		return
	}
	hashes, err := h.Store.ListHashes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, hh := range hashes {
		io.WriteString(w, hh)
		io.WriteString(w, "\n")
	}
}

func (h *HTTPServer) handleGet(w http.ResponseWriter, r *http.Request) {
	hexHash := strings.TrimPrefix(r.URL.Path, "/v1/evidence/")
	if hexHash == "" || strings.Contains(hexHash, "/") {
		http.NotFound(w, r)
		return
	}
	raw, err := hex.DecodeString(hexHash)
	if err != nil || len(raw) != sha256.Size {
		http.Error(w, "invalid evidence hash", http.StatusBadRequest)
		return
	}
	var hash [32]byte
	copy(hash[:], raw)
	b, err := h.Store.Load(platform.Identity{EvidenceHash: hash})
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(b)
}

// HTTPFetcher is the client half: it resolves an EvidenceHash by asking a peer
// TEE (or Hub) whose /v1/evidence endpoint the deployment populates. It is an
// attest.Fetcher.
type HTTPFetcher struct {
	baseURL string
	client  *http.Client
}

// NewHTTPFetcher returns a fetcher that resolves evidence from base,
// e.g. "https://tee:18090".
func NewHTTPFetcher(base string) (*HTTPFetcher, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return nil, fmt.Errorf("evidence: empty fetch base URL")
	}
	return &HTTPFetcher{baseURL: base, client: &http.Client{}}, nil
}

// Fetch resolves id.EvidenceHash against the peer's /v1/evidence endpoint. The
// caller must still validate the returned bytes through a platform verifier;
// this only guarantees the bytes hash to the value the receipt names.
func (f *HTTPFetcher) Fetch(ctx context.Context, id platform.Identity) ([]byte, error) {
	url := f.baseURL + "/v1/evidence/" + hex.EncodeToString(id.EvidenceHash[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("evidence: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNoEvidence
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("evidence: fetch %s: status %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("evidence: read %s: %w", url, err)
	}
	if sum := sha256.Sum256(b); sum != id.EvidenceHash {
		return nil, fmt.Errorf("evidence: %s returned bytes that do not match evidence hash %x",
			url, id.EvidenceHash)
	}
	return b, nil
}

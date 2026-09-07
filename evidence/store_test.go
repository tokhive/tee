package evidence

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

func idWith(evidence []byte) platform.Identity {
	return platform.Identity{
		Platform:      "simulated",
		ApplicationID: "app",
		Evidence:      evidence,
		EvidenceHash:  sha256.Sum256(evidence),
	}
}

func TestStoreRoundTrip(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	id := idWith([]byte("evidence-bytes"))
	if err := s.Put(id); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Load(id)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != "evidence-bytes" {
		t.Fatalf("Load = %q, want evidence-bytes", got)
	}
}

func TestStorePersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	id := idWith([]byte("must-survive-restart"))
	if err := s1.Put(id); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// A fresh store over the same directory must resolve what the first wrote —
	// the restart-surviving property a TEE's epoch history needs.
	s2, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore #2: %v", err)
	}
	got, err := s2.Load(id)
	if err != nil {
		t.Fatalf("Load after reopen: %v", err)
	}
	if string(got) != "must-survive-restart" {
		t.Fatalf("Load = %q after reopen", got)
	}
	if !s2.Has(id) {
		t.Fatal("Has = false after reopen")
	}
}

func TestStoreMissReturnsErrNoEvidence(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	_, err = s.Load(platform.Identity{EvidenceHash: sha256.Sum256([]byte("absent"))})
	if !errors.Is(err, ErrNoEvidence) {
		t.Fatalf("Load = %v, want ErrNoEvidence", err)
	}
}

func TestStorePutMismatchedHash(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	id := idWith([]byte("a"))
	id.EvidenceHash = sha256.Sum256([]byte("different"))
	if err := s.Put(id); err == nil {
		t.Fatal("Put accepted evidence whose bytes do not hash to its EvidenceHash")
	}
}

func TestStoreIgnoresEmptyEvidence(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Put(platform.Identity{}); err != nil {
		t.Fatalf("Put empty: %v", err)
	}
	if hashes, _ := s.ListHashes(); len(hashes) != 0 {
		t.Fatalf("ListHashes = %v, want empty", hashes)
	}
}

func TestHTTPFetcherRoundTrip(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	id := idWith([]byte("serve-me"))
	if err := s.Put(id); err != nil {
		t.Fatalf("Put: %v", err)
	}

	mux := http.NewServeMux()
	NewHTTPServer(s, mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	f, err := NewHTTPFetcher(server.URL)
	if err != nil {
		t.Fatalf("NewHTTPFetcher: %v", err)
	}
	got, err := f.Fetch(context.Background(), id)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got) != "serve-me" {
		t.Fatalf("Fetch = %q, want serve-me", got)
	}
}

func TestHTTPFetcherMiss(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	mux := http.NewServeMux()
	NewHTTPServer(s, mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	f, _ := NewHTTPFetcher(server.URL)
	_, err = f.Fetch(context.Background(), platform.Identity{EvidenceHash: sha256.Sum256([]byte("absent"))})
	if !errors.Is(err, ErrNoEvidence) {
		t.Fatalf("Fetch = %v, want ErrNoEvidence", err)
	}
}

func TestHTTPFetcherRefusesWrongBytes(t *testing.T) {
	// A peer returns bytes that do not hash to the requested evidence hash; the
	// fetcher must refuse them rather than hand an inconsistent blob to the
	// verifier.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/evidence/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("wrong-answer"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	id := platform.Identity{EvidenceHash: sha256.Sum256([]byte("expected"))}
	f, _ := NewHTTPFetcher(server.URL)
	if _, err := f.Fetch(context.Background(), id); err == nil {
		t.Fatal("Fetch accepted evidence that does not match the requested hash")
	}
}

func TestChainFallsThroughToNext(t *testing.T) {
	// First fetcher misses, second resolves: the Chain must try in order.
	missing := &Chain{}
	store, _ := NewStore(t.TempDir())
	id := idWith([]byte("chained"))
	if err := store.Put(id); err != nil {
		t.Fatalf("Put: %v", err)
	}
	chain := NewChain(missing, store)
	got, err := chain.Fetch(context.Background(), id)
	if err != nil {
		t.Fatalf("Chain.Fetch: %v", err)
	}
	if string(got) != "chained" {
		t.Fatalf("Chain.Fetch = %q, want chained", got)
	}
}

func TestChainEmptyMiss(t *testing.T) {
	chain := NewChain()
	if _, err := chain.Fetch(context.Background(), platform.Identity{}); !errors.Is(err, ErrNoEvidence) {
		t.Fatalf("Fetch = %v, want ErrNoEvidence", err)
	}
}
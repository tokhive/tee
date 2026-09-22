package hub

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// TestCredentialKeyCoalescesAConnectingFleet proves the two properties that
// matter when a TEE comes back and every agent reconnects at once: a wave of
// concurrent callers costs the TEE one round-trip, not one per agent, and a
// caller arriving afterwards still reads the TEE afresh.
//
// The second property is the one a TTL cache would break: the handler below
// rotates its key like a restarted TEE, and the later caller must see the new
// key immediately. Handing it the cached one would make every agent that
// reconnects inside the TTL window seal its token to a key the TEE can no
// longer open.
func TestCredentialKeyCoalescesAConnectingFleet(t *testing.T) {
	oldKey, err := tee.GenerateInboxKey()
	if err != nil {
		t.Fatalf("generate inbox key: %v", err)
	}
	newKey, err := tee.GenerateInboxKey()
	if err != nil {
		t.Fatalf("generate inbox key: %v", err)
	}

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold every fetch open briefly. This widens the in-flight window so
		// the whole fleet is guaranteed to pile onto one request, which keeps
		// the assertion below deterministic rather than a scheduling race.
		time.Sleep(50 * time.Millisecond)
		if n := atomic.AddInt32(&hits, 1); n == 1 {
			_ = json.NewEncoder(w).Encode(oldKey.Public())
			return
		}
		// From the second fetch on, behave like a TEE that restarted: a fresh
		// inbox key, and the old one is dead.
		_ = json.NewEncoder(w).Encode(newKey.Public())
	}))
	defer srv.Close()

	client := &HTTPTEE{BaseURL: srv.URL, Client: srv.Client()}

	const fleet = 8
	got := make([]tee.InboxPublic, fleet)
	var wg sync.WaitGroup
	for i := 0; i < fleet; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key, err := client.CredentialKey(context.Background())
			if err != nil {
				t.Errorf("credential key: %v", err)
				return
			}
			got[i] = key
		}(i)
	}
	wg.Wait()

	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("%d concurrent callers cost %d TEE fetches, want 1", fleet, n)
	}
	for i, key := range got {
		if !sameKey(key, oldKey.Public()) {
			t.Fatalf("caller %d got an unexpected key", i)
		}
	}

	// A lone caller after the wave must re-read the TEE and see the rotated
	// key: there is no cached value to serve, so there is no staleness window.
	key, err := client.CredentialKey(context.Background())
	if err != nil {
		t.Fatalf("credential key after rotation: %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Fatalf("later caller did not re-read the TEE: hits = %d, want 2", n)
	}
	if !sameKey(key, newKey.Public()) {
		t.Fatal("later caller got the pre-rotation key: a restarted TEE would reject every envelope sealed to it")
	}
}

func sameKey(a, b tee.InboxPublic) bool {
	return a.KeyID == b.KeyID && bytes.Equal(a.PublicKey, b.PublicKey)
}

// retiredRefusal is what the TEE's listener answers when a rotation retired the
// connection a request arrived on. The body is the peer-facing half; the header
// is the machine-readable one.
const retiredRefusal = "connection belongs to a retired attestation epoch; reconnect"

// requestCloseRecorder records, per attempt, whether the client asked for a
// connection of its own rather than one out of its pool. The retry below must
// set that flag: every pooled connection to a TEE that rotates is one the
// rotation may have just retired, and the pool does not know it yet.
type requestCloseRecorder struct {
	base http.RoundTripper

	mu         sync.Mutex
	perAttempt []bool
}

func (r *requestCloseRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.perAttempt = append(r.perAttempt, req.Close)
	r.mu.Unlock()
	return r.base.RoundTrip(req)
}

func (r *requestCloseRecorder) attempts() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.perAttempt...)
}

// writeExecuteStream answers with a minimal well-formed execute response: one
// response-start frame, one chunk, one receipt. That is everything
// HTTPTEE.Execute reads before returning, and nothing here is verified — the
// tests below are about the HTTP path, not about signatures.
func writeExecuteStream(t *testing.T, w http.ResponseWriter, chunk []byte) {
	t.Helper()
	receipt, err := proof.SignedReceipt{}.EncodeCanonical()
	if err != nil {
		t.Errorf("encode receipt: %v", err)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "event: %s\ndata: {\"status\":200}\n\n", tee.EventStart)
	fmt.Fprintf(w, "data: %s\n\n", chunk)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", tee.EventReceipt, base64.StdEncoding.EncodeToString(receipt))
}

// TestExecuteRetriesTheConnectionARotationRetired is the property that keeps a
// rotation invisible to buyers. A healthy rotation retires the connections it
// finds idle, and a Hub that reaches for one in that same instant is refused —
// not because anything is wrong, but because the connection it was holding
// belonged to the previous attested epoch. That refusal is safe to retry (the
// TEE's guard answers before the service allocates a sequence number, spends a
// credential, or reaches a provider), so the Hub must retry it rather than
// surface a failure it can fix by itself.
func TestExecuteRetriesTheConnectionARotationRetired(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set(tee.EpochRetiredHeader, "1")
			http.Error(w, retiredRefusal, http.StatusServiceUnavailable)
			return
		}
		writeExecuteStream(t, w, []byte("hello"))
	}))
	defer srv.Close()

	recorder := &requestCloseRecorder{base: srv.Client().Transport}
	client := &HTTPTEE{URL: srv.URL, Client: &http.Client{Transport: recorder}}

	relayed := 0
	res, err := client.Execute(context.Background(), testSpec(testProvider, "m"), nil, func([]byte) error {
		relayed++
		return nil
	})
	if err != nil {
		t.Fatalf("a retired connection reached the caller as a failure: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("TEE saw %d attempts, want 2 (one refusal, one retry)", got)
	}
	if relayed != 1 {
		t.Fatalf("onChunk ran %d times, want 1: a retry must not replay bytes the caller already took", relayed)
	}
	if len(res.Chunks) != 1 || string(res.Chunks[0]) != "hello" {
		t.Fatalf("retry produced %q, want one \"hello\" chunk", res.Chunks)
	}
	if got := recorder.attempts(); len(got) != 2 || got[0] || !got[1] {
		t.Fatalf("attempts asked for their own connection %v, want [false true]: the retry must leave the pool behind", got)
	}
}

// TestExecuteDoesNotRetryARefusalItCannotAttribute is the boundary of the
// retry. Only the rotation's own refusal carries the marker, and only the TEE's
// listener can produce it before the service runs. An unmarked 503 might be
// anything — including a refusal that was answered after the job had already
// executed — so retrying it could execute and bill the same job twice.
func TestExecuteDoesNotRetryARefusalItCannotAttribute(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "listen tcp: too many open files", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := &HTTPTEE{URL: srv.URL, Client: srv.Client()}
	_, err := client.Execute(context.Background(), testSpec(testProvider, "m"), nil, nil)
	if err == nil {
		t.Fatal("an unmarked 503 was reported as success")
	}
	if errors.Is(err, tee.ErrEpochRetired) {
		t.Fatal("an unmarked 503 was mistaken for a retired connection")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("an unattributable refusal was retried: %d attempts, want 1", got)
	}
}

// TestExecuteRetriesARetiredConnectionOnce bounds the retry. A TEE that keeps
// retiring connections has something else wrong with it, and the Hub's attempt
// budget is the Hub's to spend — not the transport's to loop on.
func TestExecuteRetriesARetiredConnectionOnce(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set(tee.EpochRetiredHeader, "1")
		http.Error(w, retiredRefusal, http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := &HTTPTEE{URL: srv.URL, Client: srv.Client()}
	_, err := client.Execute(context.Background(), testSpec(testProvider, "m"), nil, nil)
	if !errors.Is(err, tee.ErrEpochRetired) {
		t.Fatalf("err = %v, want the retired-epoch refusal", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("TEE saw %d attempts, want exactly 2", got)
	}
}

// TestCredentialKeyRetriesTheConnectionARotationRetired covers the retry on the
// other request a rotation can refuse, and the one whose failure a buyer never
// sees: /v1/credential-key. A provider agent fetches its TEE inbox key through
// this path on every reconnect, so a rotation that made it fail would surface
// as an agent registering a token for no visible reason — after a reconnect
// wave, when the fleet is least able to explain itself.
func TestCredentialKeyRetriesTheConnectionARotationRetired(t *testing.T) {
	key, err := tee.GenerateInboxKey()
	if err != nil {
		t.Fatalf("generate inbox key: %v", err)
	}
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set(tee.EpochRetiredHeader, "1")
			http.Error(w, retiredRefusal, http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(key.Public())
	}))
	defer srv.Close()

	recorder := &requestCloseRecorder{base: srv.Client().Transport}
	client := &HTTPTEE{BaseURL: srv.URL, Client: &http.Client{Transport: recorder}}

	got, err := client.CredentialKey(context.Background())
	if err != nil {
		t.Fatalf("a retired connection reached the agent as a failure: %v", err)
	}
	if !sameKey(got, key.Public()) {
		t.Fatal("the retry returned a key the TEE did not serve")
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Fatalf("TEE saw %d attempts, want 2 (one refusal, one retry)", n)
	}
	if got := recorder.attempts(); len(got) != 2 || got[0] || !got[1] {
		t.Fatalf("attempts asked for their own connection %v, want [false true]: the retry must leave the pool behind", got)
	}
}

// TestCredentialKeyRetriesARetiredConnectionOnce bounds it the same way the
// execute retry is bounded: a TEE that keeps retiring connections has something
// else wrong with it, and looping on it would turn one failure into a flood.
func TestCredentialKeyRetriesARetiredConnectionOnce(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set(tee.EpochRetiredHeader, "1")
		http.Error(w, retiredRefusal, http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := &HTTPTEE{BaseURL: srv.URL, Client: srv.Client()}
	if _, err := client.CredentialKey(context.Background()); !errors.Is(err, tee.ErrEpochRetired) {
		t.Fatalf("err = %v, want the retired-epoch refusal", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("TEE saw %d attempts, want exactly 2", got)
	}
}

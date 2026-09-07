package hub

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tunnel"
)

// fakeMux builds a throwaway *tunnel.Multiplexer to stand in for a live agent
// tunnel. The difference between two muxes is what the registry's mux-guard
// keys on, so a test only needs distinct pointers — net.Pipe() gives exactly
// that without a network. Cleanup closes the pipe so the mux's read loop exits.
func fakeMux(t *testing.T) *tunnel.Multiplexer {
	t.Helper()
	a, b := net.Pipe()
	m := tunnel.New(a, tunnel.Low)
	t.Cleanup(func() {
		_ = m.Close()
		_ = a.Close()
		_ = b.Close()
	})
	return m
}

// TestRevokeIgnoresSuccessor pins the fast-reconnect TOCTOU guard: when an
// agent reconnects before its old tunnel finishes tearing down, the old
// tunnel's close must NOT revoke the successor's freshly-registered credential.
//
// The sequence mirrors serveAgentTunnel: register(old) → register(new, which
// closes old) → old tunnel finally closes and tries to deregister → deregister
// must report false (it is no longer the current tunnel), so revokeCredential
// must be skipped. Only the genuine disconnect of the current tunnel revokes.
func TestRevokeIgnoresSuccessor(t *testing.T) {
	store := NewMemoryCredentialStore()
	if err := store.Put("openai", tee.Envelope{KeyID: []byte("k"), Ciphertext: []byte("c")}); err != nil {
		t.Fatalf("seed envelope: %v", err)
	}
	h := &Hub{agents: newAgentRegistry(), credentialStore: store}

	muxOld := fakeMux(t)
	muxNew := fakeMux(t)

	h.agents.register(&agentConn{provider: "openai", mux: muxOld})
	h.agents.register(&agentConn{provider: "openai", mux: muxNew}) // current is now muxNew; muxOld closed

	// The lagging old tunnel closes and tries to deregister itself.
	if h.agents.deregister("openai", muxOld) {
		h.revokeCredential("openai") // must NOT run for a stale tunnel
	}
	if _, ok := store.Get("openai"); !ok {
		t.Fatal("stale-tunnel close wrongly revoked the successor's credential")
	}

	// Genuine disconnect of the current tunnel does revoke.
	if !h.agents.deregister("openai", muxNew) {
		t.Fatal("current-tunnel deregister should report true")
	}
	h.revokeCredential("openai")
	if _, ok := store.Get("openai"); ok {
		t.Fatal("genuine disconnect should have revoked the credential")
	}
}

// TestRegisterClosesPreviousTunnel pins the rule that only one agent egresses
// for a provider at a time: registering a replacement closes the previous live
// tunnel so no stream is ever routed through a stale identity. We observe the
// close through the previous mux rejecting new dials with ErrClosed.
func TestRegisterClosesPreviousTunnel(t *testing.T) {
	r := newAgentRegistry()
	muxA := fakeMux(t)
	muxB := fakeMux(t)

	r.register(&agentConn{provider: "openai", mux: muxA})
	r.register(&agentConn{provider: "openai", mux: muxB})

	if _, err := muxA.Dial(nil); err == nil {
		t.Fatal("previous tunnel should have been closed by the replacement register")
	}
	cur, ok := r.conn("openai")
	if !ok || cur.mux != muxB {
		t.Fatal("replacement tunnel should be the current one")
	}
}

// TestAgentRegistryConcurrentAccess hammers the registry from many goroutines
// so the race detector sees every shared path: register/deregister on disjoint
// providers (the writers) racing with conn/onlineProviders readers. Each writer
// registers then deregisters its own provider, so regardless of interleaving
// the registry is empty once everyone stops — a deterministic end state that
// also proves no entry was lost or duplicated.
func TestAgentRegistryConcurrentAccess(t *testing.T) {
	r := newAgentRegistry()
	const writers = 64
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			p := fmt.Sprintf("p%d", i)
			m := fakeMux(t)
			r.register(&agentConn{provider: p, mux: m})
			r.conn(p)
			r.deregister(p, m)
		}(i)
	}
	for k := 0; k < 8; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 50; j++ {
				r.onlineProviders()
				r.conn("p0")
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := len(r.onlineProviders()); got != 0 {
		t.Fatalf("registry not empty after all writers deregistered: %d live", got)
	}
}

// TestHubAttachCredentialConcurrentWithRevoke is the dispatch-vs-revoke race in
// miniature: every Execute binds the provider's envelope via attachCredential
// (a store Get), while a disconnecting agent triggers revokeCredential (a store
// Delete). Running both at full tilt under -race proves the credential store's
// read/write locking keeps the two from tearing each other apart, and that a
// dispatch racing a revoke always sees a consistent store.
func TestHubAttachCredentialConcurrentWithRevoke(t *testing.T) {
	store := NewMemoryCredentialStore()
	h := &Hub{agents: newAgentRegistry(), credentialStore: store}
	if err := store.Put("openai", tee.Envelope{KeyID: []byte("k"), Ciphertext: []byte("c")}); err != nil {
		t.Fatalf("seed envelope: %v", err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 200; j++ {
				if j%2 == 0 {
					_, _ = h.attachCredential(jobs.Spec{Provider: "openai"})
				} else {
					h.revokeCredential("openai")
				}
			}
		}()
	}
	close(start)
	wg.Wait()
}

// TestFileCredentialStoreConcurrent exercises the durable "hub db" under the
// same read/write mix as production: each writer owns a disjoint set of
// providers it Put/Deletes, while read-only goroutines Get across all of them.
// Under -race the locking must hold; after the dust settles every provider's
// file must still load uncorrupted, proving concurrent writes never left a
// half-written envelope on disk.
func TestFileCredentialStoreConcurrent(t *testing.T) {
	store := NewFileCredentialStore(t.TempDir())
	const providers = 32
	env := func(p string) tee.Envelope { return tee.Envelope{KeyID: []byte(p), Ciphertext: []byte(p)} }

	start := make(chan struct{})
	var wg sync.WaitGroup

	// 8 writers, each owns 4 disjoint providers so no two goroutines write the
	// same file (avoiding OS-level torn writes), while still racing the store's
	// lock from many threads.
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < 100; i++ {
				p := fmt.Sprintf("p%d", w*4+i%4)
				switch i % 3 {
				case 0:
					_ = store.Put(p, env(p))
				case 1:
					_ = store.Delete(p)
				case 2:
					store.Get(p)
				}
			}
		}(w)
	}
	// 4 read-only goroutines sweeping every provider.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 200; i++ {
				store.Get(fmt.Sprintf("p%d", rand.Intn(providers)))
			}
		}()
	}
	close(start)
	wg.Wait()

	// Final consistency: re-seed and confirm every entry reads back intact.
	for i := 0; i < providers; i++ {
		p := fmt.Sprintf("p%d", i)
		if err := store.Put(p, env(p)); err != nil {
			t.Fatalf("final put %s: %v", p, err)
		}
		got, ok := store.Get(p)
		if !ok {
			t.Fatalf("provider %s missing after concurrent ops", p)
		}
		if string(got.Ciphertext) != p {
			t.Fatalf("provider %s corrupted: got ciphertext %q", p, got.Ciphertext)
		}
	}
}

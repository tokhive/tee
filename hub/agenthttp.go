package hub

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tunnel"
)

// RelayKeyHeader is the HTTP header the TEE sets on its dial-in to the Hub's
// TeeRelay endpoint to present the relay key. It is a separate secret from the
// agent gate's: the two endpoints face different audiences, and a key that
// admits a TEE must not admit an agent.
const RelayKeyHeader = "X-TokenHive-Relay-Key"

// guardHandler wraps a stream open handler so a panic on one stream cannot take
// the whole Hub process down with it: the stream is closed and the tunnel is
// left to fail on its own, instead of every other tenant's traffic dying with
// the process. It is a backstop, not a licence — the handlers below are
// expected not to panic.
func guardHandler(fn func(*tunnel.Stream, []byte)) func(*tunnel.Stream, []byte) {
	return func(s *tunnel.Stream, open []byte) {
		defer func() {
			if recover() != nil {
				_ = s.Close()
			}
		}()
		fn(s, open)
	}
}

// AgentGate is the HTTP gateway a Provider Agent dials to come online. It
// enforces the key gate, then serves the agent's control stream: the
// first stream the agent opens must be an AgentRegister (which carries the
// provider's token sealed to the TEE), and while that stream stays open the
// agent counts as online. The returned handler is stateless and safe to mount
// on a ServeMux (e.g. cmd/hub's resident service).
func (h *Hub) AgentGate(upgrader websocket.Upgrader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authedProvider, ok := h.authenticateAgent(r.Header.Get(AgentProviderHeader),
			[]byte(r.Header.Get(AgentKeyHeader)))
		if !ok {
			http.Error(w, "bad agent key", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		go h.serveAgentTunnel(conn, authedProvider)
	})
}

// authenticateAgent admits a dial-in and reports which provider the presented
// key was issued for. There is no shared-key mode: every dial-in must name a
// provider on AgentProviderHeader and present exactly the key provisioned for
// it, so the gate always returns the provider the key was bound to. A Hub with
// no per-provider keys configured admits nothing.
func (h *Hub) authenticateAgent(provider string, presented []byte) (string, bool) {
	secret, ok := h.agentKeys[provider]
	if !ok || !agentKeyMatches(presented, secret) {
		return "", false
	}
	return provider, true
}

// CredentialKeyHandler serves the TEE's inbox public key to provider agents:
// GET /v1/credential-key. Agents fetch it (through the Hub, over ordinary
// HTTP) and encrypt their tokens to it, so the Hub relays only ciphertext.
func (h *Hub) CredentialKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	key, err := h.CredentialKey(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", tee.CredentialKeyContentType)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(key)
}

// serveAgentTunnel runs one agent's dialed-in tunnel to its end. The agent's
// control stream drives the lifetime: when it registers, the tunnel becomes
// schedulable; when the control stream closes, the agent drops offline and the
// tunnel is torn down.
//
// authedProvider is the provider the dial-in's key was issued for (never empty:
// the gate only admits a key that resolves to a provider). The register must
// name exactly that provider, so a key for one provider cannot be used to come
// online as another.
func (h *Hub) serveAgentTunnel(conn *websocket.Conn, authedProvider string) {
	mux := tunnel.New(tunnel.WrapWS(conn), tunnel.Low)
	// The control-stream handler is the only authority on the tunnel's end: it
	// closes over done so that serveAgentTunnel unwinds exactly when the agent's
	// lease ends (or an unregistered agent hangs up its first stream).
	//
	// Exactly one stream is the control stream and done is closed exactly once.
	// A hostile agent can open further streams on its own tunnel — nothing in
	// the multiplexer stops it — and every one of them would otherwise run this
	// handler again: a second close(done) is a panic, and an unprotected panic
	// would take the whole Hub down. The claim makes only the first stream the
	// control stream; the Once makes the close idempotent.
	done := make(chan struct{})
	var (
		endOnce sync.Once
		claimed atomic.Bool
	)
	end := func() { endOnce.Do(func() { close(done) }) }
	mux.Serve(guardHandler(func(control *tunnel.Stream, open []byte) {
		if !claimed.CompareAndSwap(false, true) {
			// An agent never opens a second stream: the Hub owns the dial
			// direction. Refuse it without touching the lease.
			_ = control.Close()
			return
		}
		defer end()
		var reg AgentRegister
		if err := json.Unmarshal(open, &reg); err != nil {
			_ = control.Close()
			return
		}
		// The provider name reaches a filesystem path in the credential store,
		// so it must be validated before it is stored, not merely checked for
		// emptiness: an unchecked name is a path-traversal write (see
		// FileCredentialStore).
		if err := jobs.ValidateProviderName(reg.Provider); err != nil {
			_ = control.Close()
			return
		}
		if authedProvider != "" && reg.Provider != authedProvider {
			// The key was issued for another provider: the register is a
			// claim to a name this agent did not authenticate as.
			_ = control.Close()
			return
		}
		price, ok := h.agentPrice(reg)
		if !ok {
			_ = control.Close()
			return
		}
		// The token must be in the TEE before the agent counts as online:
		// making a credential-less agent schedulable would route jobs straight
		// into a refusal. The envelope is ciphertext to the Hub.
		if err := h.deliverCredential(reg); err != nil {
			_ = control.Close()
			return
		}
		h.agents.register(&agentConn{provider: reg.Provider, price: price, models: reg.Models, mux: mux})
		// The control stream is the agent's lease on being online: drain it until
		// it closes, then drop the tunnel from the scheduler and revoke the token
		// so it is never used while its agent is offline. Revoking is gated on the
		// tunnel having been the current one: a stale agent that lost a race to a
		// replacement must not delete the replacement's freshly-registered token.
		_, _ = io.Copy(io.Discard, control)
		if h.agents.deregister(reg.Provider, mux) {
			h.revokeCredential(reg.Provider)
		}
	}))
	<-done
	_ = mux.Close()
	_ = conn.Close()
}

// agentPrice resolves the effective card an agent will be quoted: its own card
// when declared and valid, the platform default otherwise. ok is false when the
// provider has no platform default at all, which makes the agent unrecognized.
func (h *Hub) agentPrice(reg AgentRegister) (RateCard, bool) {
	if reg.SelfPrice != nil {
		if err := reg.SelfPrice.Validate(); err == nil {
			return *reg.SelfPrice, true
		}
		// An invalid self-price is a misreport, not a reason to charge less than
		// the platform default: fall through rather than honour a malformed card.
	}
	card, ok := h.rates[reg.Provider]
	return card, ok
}

// TeeRelay is the hub endpoint the TEE dials to carry egress. It wraps the
// connection in a multiplexed tunnel; each stream the TEE opens names a provider
// and an upstream host, and the Hub bridges that stream into a fresh stream on
// the named online agent's tunnel. The bridge moves ciphertext only.
//
// The endpoint is a general-purpose egress path through every online agent's
// tunnel — anything that can reach it can open a stream to any provider's
// upstream host. When a relay key is configured the dial-in must present it;
// with none the endpoint accepts any dialer, which is the deliberate dev
// stance (see Config.RelaySecret).
func (h *Hub) TeeRelay(upgrader websocket.Upgrader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(h.relaySecret) > 0 && !agentKeyMatches([]byte(r.Header.Get(RelayKeyHeader)), h.relaySecret) {
			http.Error(w, "bad relay key", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		mux := tunnel.New(tunnel.WrapWS(conn), tunnel.Low)
		mux.Serve(guardHandler(h.relayStream))
	})
}

// relayStream bridges one TEE-initiated stream into the matching agent tunnel.
func (h *Hub) relayStream(teeStream *tunnel.Stream, open []byte) {
	defer teeStream.Close()
	var req RelayOpen
	if err := json.Unmarshal(open, &req); err != nil {
		return
	}
	agent, ok := h.agents.conn(req.Provider)
	if !ok {
		return
	}
	meta, _ := json.Marshal(UpstreamOpen{Host: req.Host})
	agentStream, err := agent.mux.Dial(meta)
	if err != nil {
		return
	}
	defer agentStream.Close()
	tunnel.Bridge(teeStream, agentStream)
}

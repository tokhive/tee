package hub

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tunnel"
)

// AgentGate is the HTTP gateway a Provider Agent dials to come online. It
// enforces the shared-key gate, then serves the agent's control stream: the
// first stream the agent opens must be an AgentRegister (which carries the
// provider's token sealed to the TEE), and while that stream stays open the
// agent counts as online. The returned handler is stateless and safe to mount
// on a ServeMux (e.g. cmd/hub's resident service).
func (h *Hub) AgentGate(upgrader websocket.Upgrader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !agentKeyMatches([]byte(r.Header.Get(AgentKeyHeader)), h.agentSecret) {
			http.Error(w, "bad agent key", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		go h.serveAgentTunnel(conn)
	})
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
func (h *Hub) serveAgentTunnel(conn *websocket.Conn) {
	mux := tunnel.New(tunnel.WrapWS(conn), tunnel.Low)
	// The control-stream handler is the only authority on the tunnel's end: it
	// closes over done so that serveAgentTunnel unwinds exactly when the agent's
	// lease ends (or an unregistered agent hangs up its first stream).
	done := make(chan struct{})
	mux.Serve(func(control *tunnel.Stream, open []byte) {
		defer close(done)
		var reg AgentRegister
		if err := json.Unmarshal(open, &reg); err != nil {
			_ = control.Close()
			return
		}
		if reg.Provider == "" {
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
		h.agents.register(&agentConn{provider: reg.Provider, price: price, mux: mux})
		// The control stream is the agent's lease on being online: drain it until
		// it closes, then drop the tunnel from the scheduler and revoke the token
		// so it is never used while its agent is offline. Revoking is gated on the
		// tunnel having been the current one: a stale agent that lost a race to a
		// replacement must not delete the replacement's freshly-registered token.
		_, _ = io.Copy(io.Discard, control)
		if h.agents.deregister(reg.Provider, mux) {
			h.revokeCredential(reg.Provider)
		}
	})
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
func (h *Hub) TeeRelay(upgrader websocket.Upgrader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		mux := tunnel.New(tunnel.WrapWS(conn), tunnel.Low)
		mux.Serve(h.relayStream)
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

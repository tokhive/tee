package hub

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tunnel"
)

// AgentGate is the HTTP gateway a Provider Agent dials to come online. It
// enforces the shared-key gate, then serves the agent's control stream: the
// first stream the agent opens must be an AgentRegister, and while that stream
// stays open the agent counts as online. The returned handler is stateless and
// safe to mount on a ServeMux (e.g. cmd/hub's resident service).
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
		h.agents.register(&agentConn{provider: reg.Provider, price: price, mux: mux})
		// The control stream is the agent's lease on being online: drain it until
		// it closes, then drop the tunnel from the scheduler.
		_, _ = io.Copy(io.Discard, control)
		h.agents.deregister(reg.Provider, mux)
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
	bridge(teeStream, agentStream)
}

// bridge copies bytes in both directions until either side closes. The first
// direction to finish closes both ends, which unblocks the other goroutine: a
// half-open relay would otherwise pin a stream pair forever.
func bridge(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
		_ = a.Close()
		_ = b.Close()
	}()
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
		_ = a.Close()
		_ = b.Close()
	}()
	<-done
}

// ErrAgentOffline reports a relay attempt for a provider whose agent is not
// online. It is informational; callers (the transport) treat it as a plain
// connection failure and hand the job to the next-cheapest provider.
var ErrAgentOffline = errors.New("no online agent for provider")

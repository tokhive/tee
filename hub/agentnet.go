package hub

import (
	"crypto/subtle"
	"errors"
	"sync"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tunnel"
)

// This file is the server half of the reverse tunnel. A Provider Agent behind a
// home NAT cannot be dialed, so it dials the Hub and keeps one multiplexed
// WebSocket open. The Hub registers each live agent's tunnel along with the
// price it wants to charge (its own rate card, or the Hub's platform default if
// it reports none), and the scheduler only ever routes new work to an agent that
// is currently online. TEE↔upstream traffic then flows as a relay: the TEE opens
// a stream on its own tunnel to the Hub, and the Hub bridges that stream into a
// matching stream on the chosen agent's tunnel.
//
// The wire contract (message shapes, header names) lives in this package so both
// the Hub and the provider.Agent client import one definition.

// Errors from the agent dial-in gate.
var (
	// ErrBadAgentKey means a connection presented a shared key that does not
	// match the Hub's. The key is the only thing standing between a discovered
	// relay endpoint and a free general-purpose proxy, so a mismatch is refused
	// before any stream is accepted.
	ErrBadAgentKey = errors.New("agent dial-in: bad shared key")
	// ErrAgentUnrecognized means a control stream registered a provider name the
	// Hub has no rate for, inside a tunnel that already authenticated.
	ErrAgentUnrecognized = errors.New("agent dial-in: unknown provider")
)

// AgentKeyHeader is the HTTP header an agent sets on its dial-in request to
// present the shared key. It is deliberate precedent over Authorization/Bearer
// so the Hub's agent gate and the TEE's user-facing API never confuse their
// audiences.
const AgentKeyHeader = "X-TokenHive-Agent-Key"

// deliverCredential stores an agent-registered envelope in the Hub's
// credential store. The Hub holds only ciphertext — an envelope sealed to the
// TEE's inbox key — which it later attaches to every job it dispatches to this
// provider, so the token never exists in Hub memory.
func (h *Hub) deliverCredential(reg AgentRegister) error {
	if reg.Credential == nil {
		return errors.New("agent dial-in: registration carries no credential")
	}
	return h.credentialStore.Put(reg.Provider, *reg.Credential)
}

// revokeCredential drops a provider's envelope from the store because its
// agent went offline. Best effort: an agent that disappears mid-request may
// already have been replaced, and a dropped envelope only costs the next
// registration.
func (h *Hub) revokeCredential(provider string) {
	_ = h.credentialStore.Delete(provider)
}

// agentKeyMatches compares a presented key to the Hub's shared secret in
// constant time. The key arrives over the network, so mismatches must not leak
// where they differ (cf. the agent's credential check, which follows the same
// rule).
func agentKeyMatches(presented, secret []byte) bool {
	if len(secret) == 0 {
		return false
	}
	if len(presented) != len(secret) {
		// Length is not secret here; only a successful full match admits a
		// tunnel, and a length mismatch is already a full mismatch.
		return false
	}
	return subtle.ConstantTimeCompare(presented, secret) == 1
}

// AgentRegister is the open metadata of the control stream an agent opens
// immediately after its dial-in authenticates. It announces who the agent is,
// what it wants to charge, and — sealed inside Credential — the provider's
// access token. The stream carrying it is the agent's only live handle on the
// Hub: while it stays open the agent is online, and when it closes the Hub
// drops the tunnel from the scheduler and revokes the credential with the TEE.
type AgentRegister struct {
	// Provider names whom this agent egresses for. It must match a provider the
	// Hub has a rate for, or the tunnel is refused.
	Provider string `json:"provider"`
	// DisplayName is a human label for the agent. Optional.
	DisplayName string `json:"display_name,omitempty"`
	// SelfPrice, when set, is the agent's own rate card. A nil SelfPrice means
	// the agent accepts the Hub's platform default for its provider.
	SelfPrice *RateCard `json:"self_price,omitempty"`
	// Models is the set of model IDs the agent's upstream can serve. Empty
	// means undeclared: the Hub treats such an agent as serving any model, so
	// scheduling still tries it and falls back on upstream refusal exactly as
	// it does today. When non-empty it is a soft capability hint: the Hub
	// prefers candidates that declare the model, and a model nobody declares
	// is dispatched to undeclared candidates rather than refused outright.
	Models []string `json:"models,omitempty"`
	// Credential is the provider's token sealed to the TEE's inbox public key
	// (tee.EncryptCredential). The Hub only ever holds this ciphertext: it
	// stores the envelope in its credential store and attaches it to every job
	// it dispatches to this provider, and the plaintext never passes through
	// Hub memory.
	Credential *tee.Envelope `json:"credential,omitempty"`
}

// UpstreamOpen is the open metadata on a relay stream the Hub opens toward an
// agent: the upstream host the agent must dial. The agent never learns anything
// beyond that address — everything else on the stream is ciphertext belonging to
// the TEE's session, which the agent is deliberately not party to.
type UpstreamOpen struct {
	Host string `json:"host"`
}

// RelayOpen is the open metadata on a stream the TEE opens toward the Hub's
// relay endpoint. It names the online provider's tunnel to bridge into and the
// upstream host to reach on that tunnel.
type RelayOpen struct {
	Provider string `json:"provider"`
	Host     string `json:"host"`
}

// agentConn is one online agent: its live multiplexed tunnel, the price the
// Hub quotes for it (the agent's own card when it declared one, the platform
// default otherwise), and the models it declared it can serve.
type agentConn struct {
	provider string
	price    RateCard
	models   []string
	mux      *tunnel.Multiplexer
}

// serves reports whether the agent declares the model. An undeclared list
// means the agent serves anything (no capability information was reported), so
// serves is true for every model.
func (a *agentConn) serves(model string) bool {
	if len(a.models) == 0 {
		return true
	}
	for _, m := range a.models {
		if m == model {
			return true
		}
	}
	return false
}

// agentRegistry tracks which agents are online right now. It is the Hub's view
// of supply: a provider with a live tunnel here is schedulable; one without one
// is not, no matter what its static rate card says.
type agentRegistry struct {
	mu     sync.RWMutex
	online map[string]*agentConn
}

func newAgentRegistry() *agentRegistry {
	return &agentRegistry{online: make(map[string]*agentConn)}
}

// conn returns the live agent tunnel for a provider, if one is online.
func (r *agentRegistry) conn(provider string) (*agentConn, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.online[provider]
	return a, ok
}

// onlineProviders returns every provider with a live tunnel, in no particular
// order (callers sort).
func (r *agentRegistry) onlineProviders() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.online))
	for p := range r.online {
		out = append(out, p)
	}
	return out
}

// register installs a freshly-authenticated agent as online. Any previous live
// tunnel for the same provider is closed: only one agent egresses for a provider
// at a time, so no stream is ever routed through a stale or duplicate identity.
func (r *agentRegistry) register(a *agentConn) {
	r.mu.Lock()
	prev, ok := r.online[a.provider]
	r.online[a.provider] = a
	r.mu.Unlock()
	if ok && prev != a {
		_ = prev.mux.Close()
	}
}

// deregister removes an agent by provider. It returns whether this tunnel was
// the current one — i.e. whether it actually went offline. It no-ops (false)
// if the tunnel is no longer the current one, so an agent racing its own
// replacement cannot unregister its successor; that also means its credential
// must not be revoked, because the successor's registration stands.
func (r *agentRegistry) deregister(provider string, mux *tunnel.Multiplexer) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.online[provider]; ok && cur.mux == mux {
		delete(r.online, provider)
		return true
	}
	return false
}

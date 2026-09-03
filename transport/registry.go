package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// ErrUnknownEndpoint means no network endpoint is registered for a provider.
// The data path treats it as a refusal to build a connection: it never dials a
// provider whose egress is unknown, because routing a credential through a
// machine nobody allocated to that provider would leak the very isolation the
// registry exists to provide.
var ErrUnknownEndpoint = errors.New("no network endpoint registered for provider")

// Endpoint tells the data path how to reach a provider's egress.
//
// It is pure network-plumbing data, not business rules. Which provider a
// request belongs to (Provider in tee.Request) is decided by the Hub; this
// table only maps that name to the TCP route its Agent publishes.
type Endpoint struct {
	// AgentAddr is the provider's Provider Agent address. Empty means dial the
	// target host directly — valid for a TEE co-located with the provider, or a
	// local demo. When set, all provider traffic is tunnelled through the agent
	// as opaque TLS bytes, so the credential never exists on a wire the TEE
	// does not end.
	AgentAddr string `json:"agent_addr,omitempty"`

	// Username and Password authenticate the TEE to a SOCKS5 agent (RFC 1929)
	// that requires credentials. Both empty offers no authentication.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// Auth returns the SOCKS5 credentials this endpoint carries.
func (e Endpoint) Auth() *SOCKS5Auth {
	if e.Username == "" && e.Password == "" {
		return nil
	}
	return &SOCKS5Auth{Username: e.Username, Password: e.Password}
}

// EndpointRegistry resolves a provider name to the network endpoint its egress
// should use. It is intentionally a narrow read-only view over a mutable map,
// so the data path never needs to know where the table came from — the Hub in
// production, a file in the simulation.
type EndpointRegistry struct {
	mu sync.RWMutex
	m  map[string]Endpoint
}

// NewRegistry returns an empty registry. Providers are added with Set.
func NewRegistry() *EndpointRegistry {
	return &EndpointRegistry{m: make(map[string]Endpoint)}
}

// Endpoint resolves provider to its egress route.
func (r *EndpointRegistry) Endpoint(provider string) (Endpoint, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.m[provider]
	return e, ok
}

// Set installs or replaces the endpoint for provider.
func (r *EndpointRegistry) Set(provider string, e Endpoint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[provider] = e
}

// LoadEndpointsFile reads a JSON map of provider name to endpoint
// ({ "<provider>": {"agent_addr": "127.0.0.1:18092"} }) and installs every entry.
//
// It is the file-backed pathway for the local simulation; production feeds the
// same registry over a management API instead. Unknown keys are ignored so a
// shared file can describe more providers than one TEE serves.
func (r *EndpointRegistry) LoadEndpointsFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read endpoints %s: %w", path, err)
	}
	var m map[string]Endpoint
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("decode endpoints %s: %w", path, err)
	}
	r.mu.Lock()
	for p, e := range m {
		r.m[p] = e
	}
	r.mu.Unlock()
	return nil
}
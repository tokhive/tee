package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
)

// TestPoliciesHandlerServesTheDeployedWhitelist pins the buyer/seller-facing
// /v1/policies contract: it serves the one document the enclave enforces — the
// allowed hosts, the request-family rules, and the hash — derived from the same
// policy file the TEE loads.
func TestPoliciesHandlerServesTheDeployedWhitelist(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)
	if err := shared.EnsureDefaults(); err != nil {
		t.Fatalf("ensure defaults: %v", err)
	}
	doc, err := shared.LoadPolicy()
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	rec := httptest.NewRecorder()
	policiesHandler(doc).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/policies", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/policies = %d, want 200", rec.Code)
	}

	var body struct {
		PolicyHash  string `json:"policy_hash"`
		Unavailable bool   `json:"unavailable"`
		Policy      *struct {
			Hosts []string          `json:"hosts"`
			Rules []json.RawMessage `json:"rules"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /v1/policies body %q: %v", rec.Body.String(), err)
	}
	if body.Unavailable {
		t.Fatal("a loaded policy must not be reported unavailable")
	}
	if body.PolicyHash == "" {
		t.Fatal("missing policy_hash")
	}
	if body.Policy == nil {
		t.Fatal("missing policy document")
	}
	if len(body.Policy.Hosts) == 0 {
		t.Fatal("the policy names no hosts")
	}
	if len(body.Policy.Rules) == 0 {
		t.Fatal("the policy declares no rules")
	}
	// The two real upstreams the default whitelist exists to admit, so a buyer
	// can see up front which APIs this deployment reaches.
	for _, want := range []string{"api.openai.com", "api.anthropic.com"} {
		if !strings.Contains(strings.Join(body.Policy.Hosts, " "), want) {
			t.Fatalf("hosts %v do not include %s", body.Policy.Hosts, want)
		}
	}
}

// TestPoliciesHandlerUnloadedPolicyIsUnavailable pins the honest failure mode:
// when the whitelist could not be loaded the endpoint says so instead of
// serving a made-up policy.
func TestPoliciesHandlerUnloadedPolicyIsUnavailable(t *testing.T) {
	rec := httptest.NewRecorder()
	policiesHandler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/policies", nil))

	var body struct {
		Unavailable bool `json:"unavailable"`
		Policy      any  `json:"policy"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	if !body.Unavailable {
		t.Fatal("an unloaded policy must be reported unavailable, not a plausible whitelist")
	}
	if body.Policy != nil {
		t.Fatal("an unavailable policy must not be accompanied by a policy document")
	}
}

// TestAdmitAgainstPolicyLooksUpByHostAndPath pins the bring-up admission check:
// an agent is judged by where its models would egress, not by anything it
// declares about itself, and a deployment whose whitelist does not cover the
// route surface admits nobody rather than scheduling refusals. The judged host
// is per-provider — the agent's own upstream from the Hub's routing — so two
// sellers fronting different vendors are judged on different hosts.
func TestAdmitAgainstPolicyLooksUpByHostAndPath(t *testing.T) {
	doc := policy.Policy{
		Version: policy.VersionV1,
		Hosts:   []string{"api.openai.com", "api.anthropic.com"},
		Rules: []policy.Rule{
			{Methods: []string{"POST"}, Path: "/v1/chat/completions"},
			{Methods: []string{"POST"}, Path: "/v1/messages"},
			{Methods: []string{"POST"}, Path: "/v1/responses"},
			{Methods: []string{"GET"}, Path: realtimePath},
		},
		Limits:    policy.Limits{MaxResponseBytes: 1 << 20, MaxBodyBytes: 1 << 20},
		IssuedAt:  1,
		ExpiresAt: 2,
	}
	reg := hub.AgentRegister{Provider: "bee-9f3a"}
	hostFor := serveConfig{Host: "api.openai.com"}.HostFor

	if err := admitAgainstPolicy(&doc, hostFor)(reg); err != nil {
		t.Fatalf("a whitelisted upstream was refused: %v", err)
	}

	// The same agent, judged on a host the deployment does not reach.
	if err := admitAgainstPolicy(&doc, serveConfig{Host: "evil.example.com"}.HostFor)(reg); err == nil {
		t.Fatal("an agent behind an unlisted upstream was admitted")
	} else if !strings.Contains(err.Error(), "bee-9f3a") {
		t.Fatalf("refusal does not name the agent: %v", err)
	}

	// A whitelist missing one of the Hub's routes admits nobody: the buyer, not
	// the seller, picks the route, so admitting a partial surface would only
	// move the refusal into the TEE.
	narrow := doc
	narrow.Rules = []policy.Rule{doc.Rules[0], doc.Rules[3]}
	err := admitAgainstPolicy(&narrow, hostFor)(reg)
	if err == nil {
		t.Fatal("a whitelist missing a route admitted an agent")
	}
	if !strings.Contains(err.Error(), "/v1/messages") {
		t.Fatalf("refusal does not name the uncovered route: %v", err)
	}

	if err := admitAgainstPolicy(nil, hostFor)(reg); err == nil {
		t.Fatal("an unloaded whitelist admitted an agent")
	}
}

// TestAdmitAgainstPolicyJudgesEachProviderOnItsOwnHost pins the multi-vendor
// routing: an Anthropic seller overridden to api.anthropic.com is admitted on
// its own host even when the Hub-wide default is the OpenAI endpoint, and an
// override pointing outside the whitelist is refused at bring-up rather than
// job by job inside the TEE.
func TestAdmitAgainstPolicyJudgesEachProviderOnItsOwnHost(t *testing.T) {
	doc := policy.Policy{
		Version: policy.VersionV1,
		Hosts:   []string{"api.openai.com", "api.anthropic.com"},
		Rules: []policy.Rule{
			{Methods: []string{"POST"}, Path: "/v1/chat/completions"},
			{Methods: []string{"POST"}, Path: "/v1/messages"},
			{Methods: []string{"POST"}, Path: "/v1/responses"},
			{Methods: []string{"GET"}, Path: realtimePath},
		},
		Limits:    policy.Limits{MaxResponseBytes: 1 << 20, MaxBodyBytes: 1 << 20},
		IssuedAt:  1,
		ExpiresAt: 2,
	}
	routes := serveConfig{
		Host:          "api.openai.com",
		ProviderHosts: map[string]string{"anthropic-seller": "api.anthropic.com"},
	}.HostFor

	if err := admitAgainstPolicy(&doc, routes)(hub.AgentRegister{Provider: "openai-seller"}); err != nil {
		t.Fatalf("the default-host seller was refused: %v", err)
	}
	if err := admitAgainstPolicy(&doc, routes)(hub.AgentRegister{Provider: "anthropic-seller"}); err != nil {
		t.Fatalf("the overridden seller was refused on its own whitelisted host: %v", err)
	}

	evil := serveConfig{
		Host:          "api.openai.com",
		ProviderHosts: map[string]string{"anthropic-seller": "evil.example.com"},
	}.HostFor
	if err := admitAgainstPolicy(&doc, evil)(hub.AgentRegister{Provider: "anthropic-seller"}); err == nil {
		t.Fatal("a seller overridden to an unlisted upstream was admitted")
	}
}

// TestServeConfigHostFor pins the routing fallback: an override wins for its
// provider, everyone else keeps the Hub-wide default, and a zero map changes
// nothing — which is what keeps single-upstream deployments working untouched.
func TestServeConfigHostFor(t *testing.T) {
	def := serveConfig{Host: "127.0.0.1:18080"}
	if got := def.HostFor("openai-sim"); got != "127.0.0.1:18080" {
		t.Fatalf("HostFor without overrides = %q, want the default", got)
	}
	multi := serveConfig{
		Host:          "api.openai.com",
		ProviderHosts: map[string]string{"anthropic-seller": "api.anthropic.com"},
	}
	if got := multi.HostFor("anthropic-seller"); got != "api.anthropic.com" {
		t.Fatalf("HostFor(anthropic-seller) = %q, want the override", got)
	}
	if got := multi.HostFor("openai-seller"); got != "api.openai.com" {
		t.Fatalf("HostFor(openai-seller) = %q, want the default", got)
	}
}

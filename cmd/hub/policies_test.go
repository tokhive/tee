package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
)

// TestPoliciesHandlerListsDeployedWhitelist pins the buyer/seller-facing
// /v1/policies contract: it names every provider the enclave is configured to
// accept, the allowed hosts, the request-family rules, and the per-policy and
// policy-set hashes — a read-only mirror of the whitelist the TEE enforces,
// derived from the same policy files.
func TestPoliciesHandlerListsDeployedWhitelist(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)
	if err := shared.EnsureDefaults(); err != nil {
		t.Fatalf("ensure defaults: %v", err)
	}
	set, err := shared.LoadPolicySetAll()
	if err != nil {
		t.Fatalf("load policy set: %v", err)
	}

	rec := httptest.NewRecorder()
	policiesHandler(set).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/policies", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/policies = %d, want 200", rec.Code)
	}

	var body struct {
		PolicySetHash string `json:"policy_set_hash"`
		Unavailable   bool   `json:"unavailable"`
		Policies      []struct {
			Provider   string            `json:"provider"`
			Hosts      []string          `json:"hosts"`
			Rules      []json.RawMessage `json:"rules"`
			PolicyHash string            `json:"policy_hash"`
		} `json:"policies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /v1/policies body %q: %v", rec.Body.String(), err)
	}
	if body.Unavailable {
		t.Fatal("a loaded policy set must not be reported unavailable")
	}
	if body.PolicySetHash == "" {
		t.Fatal("missing policy_set_hash")
	}
	if len(body.Policies) != 2 {
		t.Fatalf("Policies = %d rows, want 2 (openai-sim + cheap-sim)", len(body.Policies))
	}

	seen := map[string]bool{}
	for _, p := range body.Policies {
		seen[p.Provider] = true
		if len(p.Hosts) == 0 {
			t.Fatalf("provider %q has no hosts", p.Provider)
		}
		if p.Hosts[0] != "127.0.0.1:18080" {
			t.Fatalf("provider %q host = %q, want 127.0.0.1:18080", p.Provider, p.Hosts[0])
		}
		if len(p.Rules) == 0 {
			t.Fatalf("provider %q has no rules", p.Provider)
		}
		if p.PolicyHash == "" {
			t.Fatalf("provider %q is missing its policy hash", p.Provider)
		}
	}
	if !seen["openai-sim"] || !seen["cheap-sim"] {
		t.Fatalf("Policies covered %v, want both openai-sim and cheap-sim", seen)
	}
}

// TestPoliciesHandlerEmptySetIsUnavailable pins the honest failure mode: when
// the whitelist could not be produced the endpoint says so instead of serving a
// made-up policy.
func TestPoliciesHandlerEmptySetIsUnavailable(t *testing.T) {
	rec := httptest.NewRecorder()
	policiesHandler(policy.NewSet()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/policies", nil))

	var body struct {
		Unavailable bool `json:"unavailable"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	if !body.Unavailable {
		t.Fatal("an empty policy set must be reported unavailable, not a plausible whitelist")
	}
}
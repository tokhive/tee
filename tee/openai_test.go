package tee

import (
	"bytes"
	"context"
	"testing"

	"github.com/tokhive/tee/policy"
)

// Exercise the shipped whitelist and sealed API key together, rather than a
// permissive test policy that could hide a deployment-only refusal.
func TestExecuteOpenAIPlatformWithDefaultPolicy(t *testing.T) {
	doc, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, path, body string
		stream                   bool
	}{
		{"responses", "POST", "/v1/responses", `{"model":"gpt-4o","input":"hello"}`, false},
		{"responses stream", "POST", "/v1/responses", `{"model":"gpt-4o","input":"hello","stream":true}`, true},
		{"chat completions", "POST", "/v1/chat/completions", `{"model":"gpt-4o","messages":[]}`, false},
		{"chat completions stream", "POST", "/v1/chat/completions", `{"model":"gpt-4o","messages":[],"stream":true}`, true},
		{"list models", "GET", "/v1/models", "", false},
		{"retrieve model", "GET", "/v1/models/gpt-4o", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, func(cfg *Config) { cfg.Policy = &doc })
			body := []byte(tc.body)
			spec := env.spec(t, body)
			spec.Host = "api.openai.com:443"
			spec.Method, spec.Path, spec.Stream = tc.method, tc.path, tc.stream
			spec.Headers["openai-organization"] = "org-test"
			spec.Headers["openai-project"] = "proj-test"
			result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
			if err != nil {
				t.Fatal(err)
			}
			sent := env.transport.lastRequest(t)
			for name, want := range map[string]string{
				"authorization":       "Bearer sk-test-credential",
				"openai-organization": "org-test", "openai-project": "proj-test",
			} {
				if got := sent.Headers[name]; got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
			if sent.Host != spec.Host || sent.Path != tc.path || sent.Method != tc.method || sent.Stream != tc.stream || !bytes.Equal(sent.Body, body) {
				t.Fatal("transport did not receive the authorized request")
			}
			verifyReceipt(t, result.Receipt, spec)
			wantHash, err := doc.Hash()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(result.Receipt.Receipt.PolicyHash, wantHash[:]) {
				t.Fatal("receipt does not identify the shipped whitelist")
			}
		})
	}
}

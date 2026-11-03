package policy

import (
	"errors"
	"testing"
	"time"

	"github.com/tokhive/tee/jobs"
)

func TestDefaultWhitelistOpenAIPlatform(t *testing.T) {
	p, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	base := func(method, path string) jobs.Spec {
		return jobs.Spec{
			Version: jobs.VersionV1, JobID: make([]byte, jobs.JobIDLength), Provider: "openai",
			Method: method, Host: "api.openai.com:443", Path: path,
			Headers: map[string]string{
				"Content-Type": "application/json", "Accept": "application/json",
				"OpenAI-Organization": "org-test", "OpenAI-Project": "proj-test",
			},
			BodyHash: bodyHash(""), Nonce: make([]byte, jobs.MinNonceLength),
			ExpiresAt: now.Unix() + 60, MaxResponseBytes: 1 << 20,
		}
	}
	for _, path := range []string{"/v1/responses", "/v1/chat/completions"} {
		for _, stream := range []bool{false, true} {
			spec := base("POST", path)
			spec.Stream = stream
			if _, err := p.AuthorizeAt(spec, now); err != nil {
				t.Errorf("POST %s (stream=%v): %v", path, stream, err)
			}
		}
	}
	for _, path := range []string{"/v1/models", "/v1/models/gpt-4o"} {
		if _, err := p.AuthorizeAt(base("GET", path), now); err != nil {
			t.Errorf("GET %s: %v", path, err)
		}
	}

	// The read-only catalog must not grant model deletion, arbitrary routes,
	// query parameters or caller-controlled credentials.
	for _, tc := range []struct {
		name   string
		mutate func(*jobs.Spec)
		want   error
	}{
		{"delete model", func(s *jobs.Spec) { s.Method, s.Path = "DELETE", "/v1/models/gpt-4o" }, ErrMethodNotAllowed},
		{"create model", func(s *jobs.Spec) { s.Method = "POST" }, ErrMethodNotAllowed},
		{"path boundary", func(s *jobs.Spec) { s.Path = "/v1/models-backdoor" }, ErrPathNotAllowed},
		{"admin API", func(s *jobs.Spec) { s.Path = "/v1/organization/projects" }, ErrPathNotAllowed},
		{"billing API", func(s *jobs.Spec) { s.Path = "/v1/dashboard/billing/credit_grants" }, ErrPathNotAllowed},
		{"other host", func(s *jobs.Spec) { s.Host = "api.openai.com.evil.example:443" }, ErrHostNotAllowed},
		{"other port", func(s *jobs.Spec) { s.Host = "api.openai.com:8443" }, ErrHostNotAllowed},
		{"catalog query", func(s *jobs.Spec) { s.Query = "limit=1" }, ErrQueryNotAllowed},
		{"catalog stream", func(s *jobs.Spec) { s.Stream = true }, ErrStreamNotAllowed},
		{"caller authorization", func(s *jobs.Spec) { s.Headers["Authorization"] = "Bearer caller-key" }, jobs.ErrInvalidHeaders},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := base("GET", "/v1/models")
			tc.mutate(&spec)
			if _, err := p.AuthorizeAt(spec, now); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

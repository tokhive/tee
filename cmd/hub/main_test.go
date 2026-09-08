package main

import (
	"strings"
	"testing"
)

// buildVerifier's AWS SEV-SNP pin requirement: an allowlist entry for
// aws-sev-snp must carry a valid snp-app:<sha256 hex> -expected-app pin,
// otherwise startup must fail rather than trust any hardware-valid SNP
// application. These tests lock the fail-fast behavior in so a future
// refactor cannot silently weaken the allowlist back to platform-only trust.
func TestBuildVerifierRequiresAWSSEVSNPAppPin(t *testing.T) {
	tests := []struct {
		name        string
		allowed     string
		expectedApp string
		policyHash  string
		wantErr     string // empty = startup must succeed
	}{
		{name: "simulated default still works", allowed: "simulated"},
		{name: "aws without pin", allowed: "aws-sev-snp", wantErr: "-expected-app"},
		{name: "aws with unpinned digest", allowed: "aws-sev-snp", expectedApp: "abcd", wantErr: "-expected-app"},
		{name: "aws with short digest", allowed: "aws-sev-snp", expectedApp: "snp-app:abcd", wantErr: "pin"},
		{name: "aws with non-hex digest", allowed: "aws-sev-snp", expectedApp: "snp-app:" + strings.Repeat("z", 64), wantErr: "pin"},
		{name: "aws with valid pin", allowed: "aws-sev-snp", expectedApp: "snp-app:" + strings.Repeat("a", 64)},
		{name: "mixed allowlist with valid pin", allowed: "simulated,aws-sev-snp", expectedApp: "snp-app:" + strings.Repeat("b", 64)},
		{name: "aws with pin and policy hash", allowed: "aws-sev-snp", expectedApp: "snp-app:" + strings.Repeat("c", 64), policyHash: strings.Repeat("d", 64)},
		{name: "invalid policy hash still rejected", allowed: "simulated", policyHash: "zz", wantErr: "parse -policy-set-hash"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := buildVerifier(test.allowed, test.expectedApp, test.policyHash, "", nil)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("buildVerifier(%q, %q) = %v, want nil", test.allowed, test.expectedApp, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("buildVerifier(%q, %q) succeeded, want error containing %q", test.allowed, test.expectedApp, test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("buildVerifier error = %q, want it to contain %q", err, test.wantErr)
			}
		})
	}
}

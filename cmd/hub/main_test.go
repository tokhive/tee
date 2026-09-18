package main

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
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
		{name: "invalid policy hash still rejected", allowed: "simulated", policyHash: "zz", wantErr: "parse -policy-hash"},
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

// TestBuildTEEClientTLSModes locks in what each -tee-verify mode actually
// checks. The failure it guards against is a Hub that looks configured to verify
// the TEE and instead accepts anything: attestation mode has to fail closed on a
// peer whose certificate carries no attestation rather than degrade to "TLS
// only", and it has to keep presenting the Hub's own client certificate, which
// the TEE demands whichever way its certificate is verified.
func TestBuildTEEClientTLSModes(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)
	if err := shared.EnsureMTLSCerts(); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(simDir, shared.MTLSClientCAPath)
	validPin := "snp-app:" + strings.Repeat("ab", 32)

	t.Run("pin mode with no CA is a plain channel", func(t *testing.T) {
		cfg, err := buildTEEClientTLS(teeChannelConfig{Mode: teeVerifyPin})
		if err != nil || cfg != nil {
			t.Fatalf("buildTEEClientTLS = (%v, %v), want (nil, nil)", cfg, err)
		}
	})

	t.Run("pin mode refuses a client identity with nothing to pin against", func(t *testing.T) {
		_, err := buildTEEClientTLS(teeChannelConfig{Mode: teeVerifyPin, CertFile: "cert.pem", KeyFile: "key.pem"})
		if err == nil {
			t.Fatal("pin mode accepted a client certificate without a pin")
		}
	})

	t.Run("pin mode verifies against the named CA", func(t *testing.T) {
		cfg, err := buildTEEClientTLS(teeChannelConfig{Mode: teeVerifyPin, CAFile: caFile})
		if err != nil {
			t.Fatal(err)
		}
		if cfg == nil || cfg.VerifyPeerCertificate == nil {
			t.Fatal("pin mode installed no peer verifier")
		}
		if len(cfg.Certificates) != 1 {
			t.Fatal("pin mode did not present the Hub's client certificate")
		}
		if err := cfg.VerifyPeerCertificate([][]byte{simClientCertDER(t, simDir)}, nil); err == nil {
			t.Fatal("pin mode accepted a certificate the pinned CA did not issue")
		}
	})

	t.Run("attestation mode rejects a peer that carries no attestation", func(t *testing.T) {
		cfg, err := buildTEEClientTLS(teeChannelConfig{Mode: teeVerifyAttestation, ExpectedApp: validPin})
		if err != nil {
			t.Fatal(err)
		}
		if cfg == nil || cfg.VerifyPeerCertificate == nil {
			t.Fatal("attestation mode installed no peer verifier")
		}
		if len(cfg.Certificates) != 1 {
			t.Fatal("attestation mode did not present the Hub's client certificate")
		}
		// A well-formed certificate with no attestation extension is exactly what
		// a substituted TLS peer looks like, and it must not pass.
		err = cfg.VerifyPeerCertificate([][]byte{simClientCertDER(t, simDir)}, nil)
		if err == nil {
			t.Fatal("attestation mode accepted a peer certificate with no attestation")
		}
		if !strings.Contains(err.Error(), "attestation") {
			t.Fatalf("attestation mode rejected the peer for %v, want a missing-attestation error", err)
		}
	})

	tests := []struct {
		name    string
		opts    teeChannelConfig
		wantErr string
	}{
		{
			name:    "attestation mode refuses a competing pin",
			opts:    teeChannelConfig{Mode: teeVerifyAttestation, CAFile: caFile, ExpectedApp: validPin},
			wantErr: "-mtls-ca",
		},
		{
			name:    "attestation mode requires the application pin",
			opts:    teeChannelConfig{Mode: teeVerifyAttestation},
			wantErr: "-expected-app",
		},
		{
			name:    "attestation mode rejects a malformed pin",
			opts:    teeChannelConfig{Mode: teeVerifyAttestation, ExpectedApp: "snp-app:abc"},
			wantErr: "pin",
		},
		{
			name:    "an unknown mode is refused rather than defaulted",
			opts:    teeChannelConfig{Mode: "attest"},
			wantErr: "-tee-verify",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := buildTEEClientTLS(test.opts)
			if err == nil {
				t.Fatalf("buildTEEClientTLS(%+v) succeeded, want error containing %q", test.opts, test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("buildTEEClientTLS error = %q, want it to contain %q", err, test.wantErr)
			}
		})
	}
}

// simClientCertDER returns the DER of the simulation Hub client certificate,
// which is signed by the same CA the pin-mode subtests pin: a certificate the
// deployment distributed deliberately, so a rejection is about what it carries
// rather than about who signed it.
func simClientCertDER(t *testing.T, simDir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(simDir, shared.MTLSClientCertPath))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("simulation client certificate is not PEM")
	}
	return block.Bytes
}

func TestRequireServeKeys(t *testing.T) {
	cases := []struct {
		name      string
		serveAddr string
		agentKeys string
		relayKey  string
		wantErr   bool
	}{
		{name: "cli one-shot mode needs no keys"},
		{name: "serve mode requires agent keys", serveAddr: ":18085", relayKey: "r", wantErr: true},
		{name: "serve mode requires relay key", serveAddr: ":18085", agentKeys: "p=k", wantErr: true},
		{name: "serve mode with both keys", serveAddr: ":18085", agentKeys: "p=k", relayKey: "r"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireServeKeys(tc.serveAddr, tc.agentKeys, tc.relayKey)
			if (err != nil) != tc.wantErr {
				t.Fatalf("requireServeKeys(%q, %q, %q) err = %v, wantErr %t",
					tc.serveAddr, tc.agentKeys, tc.relayKey, err, tc.wantErr)
			}
		})
	}
}

// parseProviderHosts is fail-fast startup parsing: a typo must refuse to boot
// rather than leave a provider routed at a host it can never be admitted on.
func TestParseProviderHosts(t *testing.T) {
	t.Run("empty means no overrides", func(t *testing.T) {
		m, err := parseProviderHosts("")
		if err != nil {
			t.Fatalf("parseProviderHosts(\"\") = %v, want nil", err)
		}
		if m != nil {
			t.Fatalf("parseProviderHosts(\"\") = %v, want nil", m)
		}
	})

	t.Run("valid entries", func(t *testing.T) {
		m, err := parseProviderHosts("anthropic-seller=api.anthropic.com,openai-seller=api.openai.com:443")
		if err != nil {
			t.Fatalf("parseProviderHosts = %v, want nil", err)
		}
		if m["anthropic-seller"] != "api.anthropic.com" || m["openai-seller"] != "api.openai.com:443" {
			t.Fatalf("parseProviderHosts = %v, want both overrides", m)
		}
	})

	for _, spec := range []string{
		"not-a-pair",
		"anthropic-seller=https://api.anthropic.com",
		"anthropic-seller=api.anthropic.com/v1",
		"anthropic-seller=",
		"=api.anthropic.com",
		"BAD-NAME=api.anthropic.com",
	} {
		t.Run("reject "+spec, func(t *testing.T) {
			if _, err := parseProviderHosts(spec); err == nil {
				t.Fatalf("parseProviderHosts(%q) succeeded, want error", spec)
			}
		})
	}
}

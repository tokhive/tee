package main

import (
	"encoding/base64"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSetEnvReplacesEveryUntrustedCopy(t *testing.T) {
	env := []string{"A=1", "SNP_APP_HASH=metadata", "B=2", "SNP_APP_HASH=duplicate"}
	got := setEnv(env, "SNP_APP_HASH", "measured")
	want := []string{"A=1", "B=2", "SNP_APP_HASH=measured"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("setEnv = %#v, want %#v", got, want)
	}
}

func TestSelectedEnvGivesBrokerNoDeploymentSecrets(t *testing.T) {
	env := []string{
		"SSL_CERT_FILE=/run/bundle/ca.pem",
		"HTTPS_PROXY=http://proxy",
		"KMS_ENCLAVE_DOMAIN_KEY=secret",
		"JWT_PRIVATE_KEY=secret",
	}
	got := selectedEnv(env, "SSL_CERT_FILE", "HTTPS_PROXY")
	want := []string{"SSL_CERT_FILE=/run/bundle/ca.pem", "HTTPS_PROXY=http://proxy"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selectedEnv = %#v, want %#v", got, want)
	}
}

func TestAWSAppRunsUnprivilegedWithOnlyBindCapability(t *testing.T) {
	attr := awsAppSysProcAttr()
	if attr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("Pdeathsig = %v, want SIGKILL", attr.Pdeathsig)
	}
	if attr.Credential == nil || attr.Credential.Uid != snpAppUID || attr.Credential.Gid != snpAppUID || !attr.Credential.NoSetGroups {
		t.Fatalf("credential = %#v", attr.Credential)
	}
	want := []uintptr{unix.CAP_NET_BIND_SERVICE}
	if !reflect.DeepEqual(attr.AmbientCaps, want) {
		t.Fatalf("AmbientCaps = %#v, want %#v", attr.AmbientCaps, want)
	}
}

// TestParseMetadataEnvUnfoldsBase64UserData locks in the fix for the tee
// instance auto-stopping: EC2 returns user-data to the loader as ONE base64
// line, so the previous multi-line KEY=VAL split saw a single '=' and injected
// only one env var (TEE_PLATFORM=sevsnp never arrived -> the tee booted in
// simulated mode, failed on .sim/ca.pem, and the loader powerOff()'d the box).
func TestParseMetadataEnvUnfoldsBase64UserData(t *testing.T) {
	var buf strings.Builder
	plain := "TOKENHIVE_SIM_DIR=/tmp/tee\nTEE_PLATFORM=sevsnp\nTEE_MTLS=1"
	blob := base64.StdEncoding.EncodeToString([]byte(plain))
	got := parseMetadataEnv(&buf, blob)
	want := []string{"TOKENHIVE_SIM_DIR=/tmp/tee", "TEE_PLATFORM=sevsnp", "TEE_MTLS=1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseMetadataEnv(base64) = %#v, want %#v", got, want)
	}
	if !strings.Contains(buf.String(), "base64-decoded") {
		t.Fatalf("expected a base64-decoded log line, got: %q", buf.String())
	}
}

func TestParseMetadataEnvPassesThroughPlainText(t *testing.T) {
	var buf strings.Builder
	plain := "TEE_PLATFORM=sevsnp\nTEE_MTLS=1"
	got := parseMetadataEnv(&buf, plain)
	want := []string{"TEE_PLATFORM=sevsnp", "TEE_MTLS=1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseMetadataEnv(plain) = %#v, want %#v", got, want)
	}
	if strings.Contains(buf.String(), "base64-decoded") {
		t.Fatalf("plain text must not be rewritten as base64: %q", buf.String())
	}
}

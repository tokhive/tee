//go:build linux && !mobile

package shared

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestIsTerminalAttestWedge(t *testing.T) {
	if isTerminalAttestWedge(nil) {
		t.Fatal("nil is not a wedge")
	}
	wrapped := fmt.Errorf("ratls refresh: attest: collecting TEE attestation report: %w", syscall.ENOTTY)
	if !isTerminalAttestWedge(wrapped) {
		t.Fatal("wrapped ENOTTY should be terminal")
	}
	if !isTerminalAttestWedge(errors.New("attest: inappropriate ioctl for device")) {
		t.Fatal("string ENOTTY should be terminal")
	}
	if isTerminalAttestWedge(errors.New("dial tcp: connection refused")) {
		t.Fatal("unrelated error must not be terminal")
	}
}

func TestAttestationHealthTerminalWedgeImmediate(t *testing.T) {
	t.Setenv("SNP_ATTEST_SELFHEAL", "0")
	h := NewAttestationHealth(nil)
	h.RecordFailure(syscall.ENOTTY)
	if h.Healthy() {
		t.Fatal("a single terminal ENOTTY must gate unhealthy immediately")
	}
	h.RecordSuccess()
	if !h.Healthy() {
		t.Fatal("success must clear the wedged flag")
	}
}

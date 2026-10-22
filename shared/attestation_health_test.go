package shared

import (
	"errors"
	"testing"
)

func TestAttestationHealthConsecutive(t *testing.T) {
	t.Setenv("SNP_ATTEST_SELFHEAL", "0")
	h := NewAttestationHealth(nil)
	if !h.Healthy() {
		t.Fatal("fresh health should be healthy")
	}
	blip := errors.New("temporary network blip")
	h.RecordFailure(blip)
	h.RecordFailure(blip)
	if !h.Healthy() {
		t.Fatal("2 non-terminal failures should still be healthy")
	}
	h.RecordFailure(blip)
	if h.Healthy() {
		t.Fatal("3 non-terminal failures should gate unhealthy")
	}
	h.RecordSuccess()
	if !h.Healthy() {
		t.Fatal("success should reset the streak")
	}
}

func TestAttestationHealthNilSafe(t *testing.T) {
	var h *AttestationHealth
	h.RecordFailure(errors.New("x"))
	h.RecordSuccess()
	if !h.Healthy() {
		t.Fatal("nil AttestationHealth must report healthy")
	}
}

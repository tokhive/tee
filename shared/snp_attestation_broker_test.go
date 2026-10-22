//go:build linux && !mobile

package shared

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSNPAttestationBrokerRoundTrip(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan error, 1)
	want := awsBrokerEvidence{
		nitroTPM:  []byte("nitro document"),
		legacySEV: []byte("legacy report"),
		sev2:      []byte("v2 report"),
	}
	go func() {
		done <- serveSNPAttestationBroker(server, func(bound, appHash []byte) (awsBrokerEvidence, error) {
			if string(bound) != "bound" || !bytes.Equal(appHash, bytes.Repeat([]byte{0x42}, 32)) {
				return awsBrokerEvidence{}, errors.New("wrong request")
			}
			return want, nil
		}, func() error { return nil })
	}()

	got, err := exchangeAWSBrokerEvidence(client, []byte("bound"), bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.nitroTPM, want.nitroTPM) || !bytes.Equal(got.legacySEV, want.legacySEV) || !bytes.Equal(got.sev2, want.sev2) {
		t.Fatalf("evidence mismatch: %+v", got)
	}
	client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("broker did not stop after its exact client closed")
	}
}

func TestSNPAttestationBrokerReturnsGenerationErrorAndStaysUsable(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan error, 1)
	calls := 0
	go func() {
		done <- serveSNPAttestationBroker(server, func(_, _ []byte) (awsBrokerEvidence, error) {
			calls++
			if calls == 1 {
				return awsBrokerEvidence{}, errors.New("device busy")
			}
			return awsBrokerEvidence{[]byte("doc"), []byte("v1"), []byte("v2")}, nil
		}, func() error { return nil })
	}()

	appHash := bytes.Repeat([]byte{1}, 32)
	if _, err := exchangeAWSBrokerEvidence(client, []byte("first"), appHash); err == nil || !strings.Contains(err.Error(), "device busy") {
		t.Fatalf("first request error: %v", err)
	}
	if _, err := exchangeAWSBrokerEvidence(client, []byte("second"), appHash); err != nil {
		t.Fatalf("second request: %v", err)
	}
	client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("broker did not stop")
	}
}

func TestSNPAttestationBrokerRejectsInvalidRequestBeforeGeneration(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan error, 1)
	called := make(chan struct{}, 1)
	go func() {
		done <- serveSNPAttestationBroker(server, func(_, _ []byte) (awsBrokerEvidence, error) {
			called <- struct{}{}
			return awsBrokerEvidence{}, nil
		}, func() error { return nil })
	}()

	if _, err := client.Write([]byte("BAD!\x01\x00\x00\x00\x01" + strings.Repeat("x", 32))); err != nil {
		t.Fatal(err)
	}
	client.Close()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "magic") {
			t.Fatalf("broker error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("broker did not reject malformed request")
	}
	select {
	case <-called:
		t.Fatal("generator called for malformed request")
	default:
	}
}

func TestSNPAttestationBrokerResetUsesPrivilegedHandler(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan error, 1)
	resetCalled := make(chan struct{}, 1)
	go func() {
		done <- serveSNPAttestationBroker(server, func(_, _ []byte) (awsBrokerEvidence, error) {
			return awsBrokerEvidence{}, errors.New("unexpected attestation")
		}, func() error {
			resetCalled <- struct{}{}
			return nil
		})
	}()

	if err := exchangeSNPBrokerReset(client); err != nil {
		t.Fatal(err)
	}
	select {
	case <-resetCalled:
	default:
		t.Fatal("privileged reset handler was not called")
	}
	client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("broker did not stop")
	}
}

//go:build !mobile

package shared

import (
	"testing"
	"time"
)

func TestBootGuardMarkReadyDisarms(t *testing.T) {
	b := NewBootGuard(nil, time.Hour)
	b.MarkReady()
	select {
	case <-b.done:
	default:
		t.Fatal("MarkReady did not disarm the guard")
	}
}

func TestBootGuardMarkReadyIdempotent(t *testing.T) {
	b := NewBootGuard(nil, time.Hour)
	b.MarkReady()
	b.MarkReady() // must not panic on double close
}

func TestBootGuardNilSafe(t *testing.T) {
	var b *BootGuard
	b.MarkReady()
}

// Off SEV-SNP the guard must never arm: a dev-only path that forgets
// MarkReady would otherwise take down a workstation process.
func TestBootGuardInertOutsideSEVSNP(t *testing.T) {
	if IsSEVSNPMode() {
		t.Skip("host is SEV-SNP")
	}
	b := NewBootGuard(nil, time.Nanosecond)
	time.Sleep(20 * time.Millisecond)
	select {
	case <-b.done:
		t.Fatal("guard armed outside SEV-SNP mode")
	default:
	}
}

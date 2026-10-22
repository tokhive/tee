//go:build !mobile

package shared

import (
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Log messages emitted on the two self-reset paths. Alerting keys off these
// exact strings, so treat them as a wire contract, not free text.
const (
	BootFatalMessage = "boot fatal — self-resetting"
	BootStuckMessage = "boot deadline exceeded — self-resetting"
)

const (
	// BootReadyDeadline bounds how long a TEE may take to reach "serving".
	// A healthy boot registers and completes OT precompute in ~60s.
	BootReadyDeadline = 5 * time.Minute
	// BootResetDelay slows a reboot cycle when the failure is permanent
	// (bad config, un-allowlisted digest) so it stays diagnosable.
	BootResetDelay = 60 * time.Second
)

// FatalBootReset warm-reboots the guest after an unrecoverable boot failure.
// It never returns: returning would unwind to main, and main returning is
// exit 0, which kills PID 1 and panics the guest into a RUNNING-but-dead VM
// that nothing reaps (observed 2026-07-29, a transient cert-chain fetch).
func FatalBootReset(logger *Logger, reason error) {
	if logger != nil {
		logger.Critical(BootFatalMessage, zap.Error(reason))
		_ = logger.Sync()
	}
	// Outside SEV-SNP this is a workstation or a test host — rebooting it
	// would be catastrophic and there is no PID-1 constraint to satisfy.
	if !IsSEVSNPMode() {
		os.Exit(1)
	}
	time.Sleep(BootResetDelay)
	attestSelfReset(logger)
	// Reboot refused (no CAP_SYS_BOOT). Hold: the router health-gate and the
	// alert on BootFatalMessage cover it, and holding beats exiting 0.
	if logger != nil {
		logger.Critical("self-reset did not take effect — holding for manual intervention")
		_ = logger.Sync()
	}
	select {}
}

// BootGuard reboots the guest if it never reaches "serving". It catches what
// error returns cannot: a boot step that hangs instead of failing, and any
// future fatal path that forgets to report. Armed at process start, disarmed
// exactly once by MarkReady.
type BootGuard struct {
	once sync.Once
	done chan struct{}
}

func NewBootGuard(logger *Logger, deadline time.Duration) *BootGuard {
	b := &BootGuard{done: make(chan struct{})}
	// Inert off SEV-SNP: a missed MarkReady on a dev-only path must never
	// take down a workstation process.
	if !IsSEVSNPMode() {
		return b
	}
	go func() {
		select {
		case <-b.done:
		case <-time.After(deadline):
			FatalBootReset(logger, fmt.Errorf("%s: not serving after %s", BootStuckMessage, deadline))
		}
	}()
	return b
}

// MarkReady disarms the guard. Idempotent and nil-safe.
func (b *BootGuard) MarkReady() {
	if b == nil {
		return
	}
	b.once.Do(func() { close(b.done) })
}

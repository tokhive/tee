//go:build linux && !mobile

package shared

import (
	"errors"
	"os"
	"strings"
	"syscall"

	"go.uber.org/zap"
)

// isTerminalAttestWedge reports whether err is the sticky SEV-guest failure —
// the kernel driver wiped the VMPCK (fail-closed) so every report ioctl now
// returns ENOTTY until a reboot re-provisions the secrets page.
func isTerminalAttestWedge(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENOTTY) {
		return true
	}
	return strings.Contains(err.Error(), "inappropriate ioctl for device")
}

// captureAttestationDiag gathers reset-proof, in-guest evidence for an
// attestation failure: the raw errno, the SEV guest device state, and kernel
// ring-buffer lines mentioning the SEV/CCP path. Confidentiality-preserving
// substitute for serial-console logging (we control exactly what it emits).
func captureAttestationDiag(err error) []zap.Field {
	fields := []zap.Field{}
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		fields = append(fields, zap.String("errno", errno.Error()), zap.Int("errno_num", int(errno)))
	}
	if fi, serr := os.Stat(sevGuestDevice); serr == nil {
		fields = append(fields, zap.Bool("sev_guest_present", true), zap.String("sev_guest_mode", fi.Mode().String()))
	} else {
		fields = append(fields, zap.Bool("sev_guest_present", false), zap.String("sev_guest_stat_err", serr.Error()))
	}
	fields = append(fields, zap.Strings("kmsg", kmsgTail("sev", "ccp", "psp", "snp", "vmpck")))
	return fields
}

// kmsgTail replays /dev/kmsg via raw non-blocking syscalls and returns up to the
// last 20 lines matching any lowercase substring. Raw reads are used (not os.File)
// because Go's netpoller would park on EAGAIN and hang until the next kernel line.
func kmsgTail(match ...string) []string {
	fd, err := syscall.Open("/dev/kmsg", syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return []string{"kmsg open: " + err.Error()}
	}
	defer syscall.Close(fd)
	buf := make([]byte, 8192)
	var hits []string
	for range 100000 {
		n, rerr := syscall.Read(fd, buf)
		if errors.Is(rerr, syscall.EPIPE) {
			continue
		}
		if rerr != nil || n <= 0 {
			break
		}
		low := strings.ToLower(string(buf[:n]))
		for _, m := range match {
			if strings.Contains(low, m) {
				hits = append(hits, strings.TrimSpace(string(buf[:n])))
				break
			}
		}
	}
	if len(hits) > 20 {
		hits = hits[len(hits)-20:]
	}
	return hits
}

// attestSelfReset warm-reboots the guest (LINUX_REBOOT_CMD_RESTART) — the only
// known recovery for a wedged SEV report path. Best-effort: on missing
// CAP_SYS_BOOT it logs and returns (router health-gate + alert cover it). It
// must NOT os.Exit: as PID 1 that panics the guest into a RUNNING-but-dead VM.
func attestSelfReset(logger *Logger) {
	if os.Getenv("SNP_ATTEST_SELFHEAL") == "0" {
		if logger != nil {
			logger.Warn("attestation self-heal disabled (SNP_ATTEST_SELFHEAL=0)")
		}
		return
	}
	if !IsSEVSNPMode() {
		return
	}
	if handled, err := resetGuestThroughSNPAttestationBroker(); handled {
		if err != nil && logger != nil {
			logger.Error("attestation-broker reset failed; staying up (evicted) for manual reset", zap.Error(err))
		}
		return
	}
	syscall.Sync()
	if err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART); err != nil && logger != nil {
		logger.Error("self-reset reboot failed; staying up (evicted) for manual reset", zap.Error(err))
	}
}

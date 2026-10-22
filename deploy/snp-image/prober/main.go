// prober is a diagnostic app for SEV-SNP images. It can run behind the normal
// two-tier loader or directly as PID 1 in a test UKI. It reports TPM PCRs, UEFI
// Secure Boot variables, the firmware event log, and the SEV-SNP report to the
// serial console. Direct-PID-1 mode is used only for disposable cloud probes.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/go-sev-guest/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"golang.org/x/sys/unix"
)

const banner = "===== SNP-PROBE ====="

const (
	eventLogPath  = "/sys/kernel/security/tpm0/binary_bios_measurements"
	eventLogBegin = "===== TCG-EVENTLOG-GZIP-BASE64 BEGIN ====="
	eventLogEnd   = "===== TCG-EVENTLOG-GZIP-BASE64 END ====="
)

// buildTag is set via -ldflags "-X main.buildTag=..." so we can produce two
// binaries that differ by a few bytes and confirm PCR 8 (the app digest)
// changes between them.
var buildTag = "dev"

func main() {
	// When run as PID 1 (no-rootfs UKI: binary is the initrd /init), there is no
	// init system, so set up the pseudo-filesystems ourselves and power off at
	// the end (otherwise the kernel panics when PID 1 exits).
	if os.Getpid() == 1 {
		mountPseudo()
		defer powerOff()
	}

	out := openConsole()
	fmt.Fprintln(out, banner)
	fmt.Fprintf(out, "build_tag          = %s\n", buildTag)
	loadModules(out)

	if h, err := selfHash(); err == nil {
		fmt.Fprintf(out, "self_binary_sha256 = %s\n", hex.EncodeToString(h[:]))
	} else {
		fmt.Fprintf(out, "self_binary_sha256 ERROR: %v\n", err)
	}

	for _, bank := range []struct {
		name string
		alg  tpm2.TPMAlgID
	}{
		{"sha256", tpm2.TPMAlgSHA256},
		{"sha384", tpm2.TPMAlgSHA384},
	} {
		for _, index := range []int{4, 7, 8, 11} {
			if v, err := readPCR(index, bank.alg); err == nil {
				fmt.Fprintf(out, "PCR%d_%-6s         = %s\n", index, bank.name, hex.EncodeToString(v))
			} else {
				fmt.Fprintf(out, "PCR%d_%-6s ERROR: %v\n", index, bank.name, err)
			}
		}
	}

	for _, name := range []string{"SecureBoot", "SetupMode", "PK", "KEK", "db", "dbx"} {
		printEFIVariable(out, name)
	}

	if err := dumpEventLog(out); err != nil {
		fmt.Fprintf(out, "event_log ERROR: %v\n", err)
	}

	if m, rd, err := readSNP(); err == nil {
		fmt.Fprintf(out, "snp_measurement    = %s\n", hex.EncodeToString(m))
		fmt.Fprintf(out, "snp_report_data    = %s\n", hex.EncodeToString(rd))
	} else {
		fmt.Fprintf(out, "snp report ERROR: %v\n", err)
	}

	fmt.Fprintln(out, banner+" END")
}

// mountPseudo mounts the filesystems needed to read TPM, UEFI variable, and
// firmware event-log state when the probe runs as PID 1 without an init system.
func mountPseudo() {
	for _, m := range []struct{ src, tgt, fs string }{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
		{"devtmpfs", "/dev", "devtmpfs"},
		{"securityfs", "/sys/kernel/security", "securityfs"},
		{"efivarfs", "/sys/firmware/efi/efivars", "efivarfs"},
	} {
		_ = os.MkdirAll(m.tgt, 0o555)
		_ = syscall.Mount(m.src, m.tgt, m.fs, 0, "")
	}
}

func loadModules(out io.Writer) {
	entries, _ := os.ReadDir("/modules")
	var pending []string
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".ko" {
			pending = append(pending, entry.Name())
		}
	}
	for len(pending) != 0 {
		var failed []string
		progress := false
		for _, name := range pending {
			f, err := os.Open(filepath.Join("/modules", name))
			if err != nil {
				failed = append(failed, name)
				continue
			}
			err = unix.FinitModule(int(f.Fd()), "", 0)
			_ = f.Close()
			if err == nil || err == unix.EEXIST {
				fmt.Fprintf(out, "module_loaded      = %s\n", name)
				progress = true
			} else {
				failed = append(failed, name)
			}
		}
		if !progress {
			for _, name := range failed {
				fmt.Fprintf(out, "module %s ERROR: unresolved dependencies\n", name)
			}
			return
		}
		pending = failed
	}
}

// powerOff cleanly halts the VM after the probe so the test instance stops
// instead of leaving PID 1 exited (which the kernel treats as a panic).
func powerOff() {
	// Hold before powering off so the serial console reliably flushes and the
	// external poll can capture the output (GCP can't read serial from a
	// TERMINATED instance).
	fmt.Println("[init] probe done; holding 90s for serial capture, then power off")
	time.Sleep(90 * time.Second)
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {}
}

// openConsole returns /dev/console if it can be opened, else stdout, so the
// output reaches the GCP serial port even when run as PID-adjacent service.
func openConsole() io.Writer {
	f, err := os.OpenFile("/dev/console", os.O_WRONLY, 0)
	if err != nil {
		return os.Stdout
	}
	return f
}

func readPCR(index int, alg tpm2.TPMAlgID) ([]byte, error) {
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		tpm, err = linuxtpm.Open("/dev/tpm0")
		if err != nil {
			return nil, fmt.Errorf("open tpm: %w", err)
		}
	}
	defer tpm.Close()

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      alg,
			PCRSelect: pcrSelectBitmap(index),
		}},
	}
	resp, err := tpm2.PCRRead{PCRSelectionIn: sel}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("pcrread: %w", err)
	}
	if len(resp.PCRValues.Digests) == 0 {
		return nil, fmt.Errorf("no PCR digest returned")
	}
	return resp.PCRValues.Digests[0].Buffer, nil
}

func printEFIVariable(out io.Writer, name string) {
	paths, err := filepath.Glob(filepath.Join("/sys/firmware/efi/efivars", name+"-*"))
	if err != nil || len(paths) != 1 {
		if err == nil {
			err = fmt.Errorf("found %d files", len(paths))
		}
		fmt.Fprintf(out, "efi_var_%-10s ERROR: %v\n", name, err)
		return
	}
	b, err := os.ReadFile(paths[0])
	if err != nil {
		fmt.Fprintf(out, "efi_var_%-10s ERROR: %v\n", name, err)
		return
	}
	if len(b) < 4 {
		fmt.Fprintf(out, "efi_var_%-10s ERROR: value is %d bytes\n", name, len(b))
		return
	}
	attrs := binary.LittleEndian.Uint32(b[:4])
	value := b[4:]
	sum := sha256.Sum256(value)
	if len(value) == 1 {
		fmt.Fprintf(out, "efi_var_%-10s = %d attrs=0x%x bytes=%d sha256=%s\n", name, value[0], attrs, len(value), hex.EncodeToString(sum[:]))
		return
	}
	fmt.Fprintf(out, "efi_var_%-10s = attrs=0x%x bytes=%d sha256=%s\n", name, attrs, len(value), hex.EncodeToString(sum[:]))
}

func dumpEventLog(out io.Writer) error {
	raw, err := os.ReadFile(eventLogPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", eventLogPath, err)
	}
	gz, err := gzipBytes(raw)
	if err != nil {
		return err
	}
	rawSum := sha256.Sum256(raw)
	gzSum := sha256.Sum256(gz)
	encoded := base64.StdEncoding.EncodeToString(gz)
	fmt.Fprintf(out, "event_log_raw_bytes   = %d\n", len(raw))
	fmt.Fprintf(out, "event_log_gzip_bytes  = %d\n", len(gz))
	fmt.Fprintf(out, "event_log_b64_bytes   = %d\n", len(encoded))
	fmt.Fprintf(out, "event_log_sha256      = %s\n", hex.EncodeToString(rawSum[:]))
	fmt.Fprintf(out, "event_log_gzip_sha256 = %s\n", hex.EncodeToString(gzSum[:]))
	fmt.Fprintln(out, eventLogBegin)
	for len(encoded) > 1024 {
		fmt.Fprintln(out, encoded[:1024])
		encoded = encoded[1024:]
	}
	if len(encoded) != 0 {
		fmt.Fprintln(out, encoded)
	}
	fmt.Fprintln(out, eventLogEnd)
	return nil
}

func gzipBytes(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return nil, fmt.Errorf("gzip event log: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close event-log gzip stream: %w", err)
	}
	return buf.Bytes(), nil
}

// pcrSelectBitmap builds the 3-byte PC-Client PCR-select bitmap (PCRs 0..23)
// with the bit for index set.
func pcrSelectBitmap(index int) []byte {
	b := make([]byte, 3)
	b[index/8] |= 1 << (index % 8)
	return b
}

func readSNP() (measurement, reportData []byte, err error) {
	qp, err := client.GetQuoteProvider()
	if err != nil {
		return nil, nil, fmt.Errorf("quote provider: %w", err)
	}
	var rd [64]byte
	h, _ := selfHash()
	copy(rd[32:], h[:])
	att, err := client.GetQuoteProto(qp, rd)
	if err != nil {
		return nil, nil, fmt.Errorf("get report: %w", err)
	}
	r := att.GetReport()
	return r.GetMeasurement(), r.GetReportData(), nil
}

func selfHash() ([32]byte, error) {
	var sum [32]byte
	exe, err := os.Executable()
	if err != nil {
		return sum, err
	}
	f, err := os.Open(exe)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	hsh := sha256.New()
	if _, err := io.Copy(hsh, f); err != nil {
		return sum, err
	}
	copy(sum[:], hsh.Sum(nil))
	return sum, nil
}

// loader is the init in the R-signed base UKI. It reads the app BUNDLE (a tar
// of the app binary + its runtime files) from a separate partition, measures
// the bundle into a dedicated PCR (the cross-cloud "image digest"), extracts
// it, and executes the app. Secure Boot evidence proves that R authorized this
// loader; the loader's PCR 8 extension then binds the app identity. Legacy SEV2
// deployments still use their recorded PCR 11 base allowlist.
//
// Bundle layout (tar): ./app (entrypoint), optionally ./mpcl/pkg (MPC circuit
// stdlib) and ./etc/ssl/certs/ca-certificates.crt — the loader points the app
// at them via MPCLDIR / SSL_CERT_FILE.
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// appPCR is a non-resettable PCR left pristine (0) by our GRUB-less, IMA-off
// UKI boot (PCR 9 is NOT usable: the Linux EFI stub measures the initrd into
// it). After Extend, PCR 8 holds ONLY the app-bundle identity:
// sha256(0x00*32 || sha256(bundle)) — clean, predictable, cross-cloud-stable.
const appPCR = 8

const bundleDir = "/run/bundle"

const (
	firmwareEventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements"
	appEventLogPath      = "/run/reclaim-secure-boot-eventlog"
)

const snpAppUID = 65532

func main() {
	mountPseudo()
	out := console()
	fmt.Fprintln(out, "===== SNP-LOADER =====")
	if err := run(out); err != nil {
		fmt.Fprintln(out, "[loader] FATAL:", err)
		powerOff()
	}
}

func run(out io.Writer) error {
	blob, dev, err := readAppPartition()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(blob)
	fmt.Fprintf(out, "[loader] app_partition  = %s\n", dev)
	fmt.Fprintf(out, "[loader] app_sha256     = %s\n", hex.EncodeToString(sum[:]))

	for _, p := range []uint32{8, 9} {
		if v, err := readPCR(p); err == nil {
			fmt.Fprintf(out, "[loader] PCR%d pre-extend = %s\n", p, hex.EncodeToString(v))
		}
	}
	if err := extendPCR(appPCR, sum[:]); err != nil {
		return fmt.Errorf("extend PCR %d: %w", appPCR, err)
	}
	fmt.Fprintf(out, "[loader] extended PCR %d with app_sha256\n", appPCR)

	// Best-effort networking so a server app (e.g. tee_t) is reachable. The
	// prober doesn't need it; failures are logged and ignored.
	bringUpNetwork(out)

	if err := syscall.Mount("tmpfs", "/run", "tmpfs", 0, ""); err != nil {
		return fmt.Errorf("mount /run: %w", err)
	}
	if err := os.Chmod("/run", 0o755); err != nil {
		return fmt.Errorf("chmod /run: %w", err)
	}
	if err := stageSecureBootEventLog(); err != nil {
		return err
	}
	if err := extractTar(blob, bundleDir); err != nil {
		return fmt.Errorf("extract bundle: %w", err)
	}

	entry := filepath.Join(bundleDir, "app")
	env := os.Environ()
	// Per-deployment config (ROUTER_URL, JWT_PUBLIC_KEY, KMS vars, ...) comes from
	// VM metadata, not the measured bundle, so PCR 8 stays generic across deploys.
	env = append(env, fetchMetadataEnv(out)...)
	// Export the cross-cloud app identity (sha256 of the measured bundle) so the
	// RA-TLS layer can carry it as the PCR-8-proven payload hash.
	env = setEnv(env, "SNP_APP_HASH", hex.EncodeToString(sum[:]))
	// This value is set by the R-signed loader after untrusted metadata is read.
	// Old deployed loaders omit it and therefore remain on the SEV2 wire format.
	env = setEnv(env, "SNP_ATTESTATION_TYPE", "secure-boot")
	if exists(filepath.Join(bundleDir, "mpcl", "pkg")) {
		env = setEnv(env, "MPCLDIR", filepath.Join(bundleDir, "mpcl"))
		fmt.Fprintf(out, "[loader] MPCLDIR=%s\n", filepath.Join(bundleDir, "mpcl"))
	}
	if ca := filepath.Join(bundleDir, "etc/ssl/certs/ca-certificates.crt"); exists(ca) {
		env = setEnv(env, "SSL_CERT_FILE", ca)
		fmt.Fprintf(out, "[loader] SSL_CERT_FILE=%s\n", ca)
	}
	if isAWSGuest() {
		fmt.Fprintln(out, "[loader] starting root attestation broker and unprivileged app")
		return runAWSIsolated(entry, env, out)
	}
	fmt.Fprintf(out, "[loader] exec %s\n", entry)
	return syscall.Exec(entry, []string{entry}, env)
}

func isAWSGuest() bool {
	v, err := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	return err == nil && strings.Contains(string(v), "Amazon")
}

func runAWSIsolated(entry string, appEnv []string, out io.Writer) error {
	if err := os.MkdirAll("/tmp", 0o1777); err != nil {
		return fmt.Errorf("create /tmp: %w", err)
	}
	if err := os.Chmod("/tmp", 0o1777); err != nil {
		return fmt.Errorf("chmod /tmp: %w", err)
	}
	for _, dev := range []string{"/dev/sev-guest", "/dev/tpm0", "/dev/tpmrm0"} {
		if err := os.Chmod(dev, 0o600); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("restrict %s: %w", dev, err)
		}
	}

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("attestation broker socketpair: %w", err)
	}
	brokerFD := os.NewFile(uintptr(fds[0]), "snp-attestation-broker")
	appFD := os.NewFile(uintptr(fds[1]), "snp-attestation-client")
	defer brokerFD.Close()
	defer appFD.Close()

	broker := exec.Command(entry)
	broker.Env = append([]string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"SNP_ATTEST_BROKER_SERVER=1",
		"SNP_ATTEST_BROKER_FD=3",
		"SNP_ATTESTATION_TYPE=secure-boot",
	}, selectedEnv(appEnv, "SSL_CERT_FILE", "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy", "NO_PROXY")...)
	broker.ExtraFiles = []*os.File{brokerFD}
	broker.Stdout = out
	broker.Stderr = out
	broker.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := broker.Start(); err != nil {
		return fmt.Errorf("start attestation broker: %w", err)
	}
	brokerFD.Close()

	app := exec.Command(entry)
	app.Env = setEnv(appEnv, "SNP_ATTEST_BROKER_FD", "3")
	app.Env = setEnv(app.Env, "SNP_ATTEST_BROKER_SERVER", "")
	app.Env = setEnv(app.Env, "SNP_ATTESTATION_TYPE", "secure-boot")
	app.ExtraFiles = []*os.File{appFD}
	app.Stdout = out
	app.Stderr = out
	app.SysProcAttr = awsAppSysProcAttr()
	if err := app.Start(); err != nil {
		_ = broker.Process.Kill()
		_ = broker.Wait()
		return fmt.Errorf("start unprivileged app: %w", err)
	}
	appFD.Close()
	fmt.Fprintf(out, "[loader] app pid=%d uid=%d broker pid=%d\n", app.Process.Pid, snpAppUID, broker.Process.Pid)

	appDone := make(chan error, 1)
	brokerDone := make(chan error, 1)
	go func() { appDone <- app.Wait() }()
	go func() { brokerDone <- broker.Wait() }()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer signal.Stop(sigCh)

	select {
	case err := <-appDone:
		_ = broker.Process.Kill()
		<-brokerDone
		return fmt.Errorf("TEE app exited: %w", err)
	case err := <-brokerDone:
		_ = app.Process.Kill()
		<-appDone
		return fmt.Errorf("attestation broker exited: %w", err)
	case sig := <-sigCh:
		_ = app.Process.Signal(sig)
		select {
		case <-appDone:
		case <-time.After(15 * time.Second):
			_ = app.Process.Kill()
			<-appDone
		}
		_ = broker.Process.Kill()
		<-brokerDone
		return fmt.Errorf("TEE app stopped after signal %s", sig)
	}
}

func awsAppSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
		Credential: &syscall.Credential{
			Uid:         snpAppUID,
			Gid:         snpAppUID,
			NoSetGroups: true,
		},
		// Production SNP endpoints bind port 443. Retain only the capability
		// required for that bind; raw attestation devices stay broker-only.
		AmbientCaps: []uintptr{unix.CAP_NET_BIND_SERVICE},
	}
}

func selectedEnv(env []string, keys ...string) []string {
	wanted := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		wanted[key] = struct{}{}
	}
	var result []string
	for _, item := range env {
		key, _, ok := strings.Cut(item, "=")
		if _, include := wanted[key]; ok && include {
			result = append(result, item)
		}
	}
	return result
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			result = append(result, item)
		}
	}
	return append(result, prefix+value)
}

// readAppPartition reads the length-prefixed app bundle (tar) from the second
// partition of the boot disk (raw, no filesystem so no fs driver is needed).
// Layout: 8-byte little-endian length, then that many bytes of tar.
func readAppPartition() ([]byte, string, error) {
	for _, dev := range []string{"/dev/nvme0n1p2", "/dev/sda2", "/dev/vda2"} {
		f, err := os.Open(dev)
		if err != nil {
			continue
		}
		var hdr [8]byte
		if _, err := io.ReadFull(f, hdr[:]); err != nil {
			f.Close()
			continue
		}
		n := binary.LittleEndian.Uint64(hdr[:])
		if n == 0 || n > 1<<30 {
			f.Close()
			continue
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(f, buf); err != nil {
			f.Close()
			continue
		}
		f.Close()
		return buf, dev, nil
	}
	return nil, "", fmt.Errorf("no app partition with a valid length header found")
}

func extractTar(data []byte, dst string) error {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dst, filepath.Clean("/"+hdr.Name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		case tar.TypeSymlink:
			_ = os.Symlink(hdr.Linkname, target)
		}
	}
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// fetchMetadataEnv pulls per-deployment config (newline-separated KEY=VALUE) from
// instance metadata and returns it as process env entries: the GCE metadata
// attribute "tee-env" on GCP, or the EC2 IMDSv2 user-data on AWS. Best-effort.
func fetchMetadataEnv(out io.Writer) []string {
	body := fetchGCETeeEnv()
	if body == "" {
		body = fetchAWSUserData()
	}
	return parseMetadataEnv(out, body)
}

// parseMetadataEnv turns a KEY=VAL metadata payload into the env vars the app
// must see. Kept separate from the fetch so the base64 unfolding is unit-tested.
func parseMetadataEnv(out io.Writer, body string) []string {
	// Metadata services differ in how they ship user-data back: AWS IMDS returns
	// the raw (already base64-decoded) text, but some providers hand back the
	// whole payload as ONE base64-encoded line (which the empirical AWS runs
	// here reproduced: the loader saw the base64 blob as a single env var). When
	// the body has no newline but is valid base64 that decodes to KEY=VAL text,
	// unfold it so the split below sees real newlines.
	if body != "" && !strings.Contains(body, "\n") {
		if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body)); err == nil {
			s := string(dec)
			if strings.Contains(s, "=") {
				body = s
				fmt.Fprintln(out, "[loader] base64-decoded instance metadata env")
			}
		}
	}
	if body == "" {
		fmt.Fprintln(out, "[loader] no instance metadata env found")
		return nil
	}
	var env []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		// A value may carry literal \n escapes so a multi-line secret (e.g. a
		// PEM public key) fits on one KEY=VAL line; expand them to real
		// newlines for the app.
		k, v, _ := strings.Cut(line, "=")
		env = append(env, k+"="+strings.ReplaceAll(v, `\n`, "\n"))
	}
	fmt.Fprintf(out, "[loader] loaded %d env var(s) from instance metadata\n", len(env))
	return env
}

func fetchGCETeeEnv() string {
	req, err := http.NewRequest("GET", "http://169.254.169.254/computeMetadata/v1/instance/attributes/tee-env", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func fetchAWSUserData() string {
	cl := &http.Client{Timeout: 5 * time.Second}
	tr, err := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return ""
	}
	tr.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	tresp, err := cl.Do(tr)
	if err != nil {
		return ""
	}
	tok, _ := io.ReadAll(tresp.Body)
	tresp.Body.Close()
	ur, err := http.NewRequest("GET", "http://169.254.169.254/latest/user-data", nil)
	if err != nil {
		return ""
	}
	ur.Header.Set("X-aws-ec2-metadata-token", string(tok))
	uresp, err := cl.Do(ur)
	if err != nil {
		return ""
	}
	defer uresp.Body.Close()
	if uresp.StatusCode != http.StatusOK {
		return ""
	}
	b, _ := io.ReadAll(uresp.Body)
	return string(b)
}

// bringUpNetwork brings up lo + the primary ethernet link, runs DHCP, and
// applies the lease (IP + gateway). A link-scope host route to the gateway is
// added first so it works even when the cloud hands out a /32 (GCP does).
// loadModules inserts any bundled kernel modules (e.g. the cloud NIC driver:
// gve on GCP, ena on AWS — neither is builtin). Decompressed at build time so
// a plain finit_module suffices.
func loadModules(out io.Writer) {
	entries, _ := os.ReadDir("/modules")
	var pending []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".ko" {
			pending = append(pending, e.Name())
		}
	}
	// Retry in passes: a module may need another not yet loaded (sev-guest needs
	// tsm_report), and ReadDir order is alphabetical. Loop while a pass makes progress.
	for len(pending) > 0 {
		var failed []string
		progress := false
		for _, name := range pending {
			f, err := os.Open(filepath.Join("/modules", name))
			if err != nil {
				continue
			}
			err = unix.FinitModule(int(f.Fd()), "", 0)
			f.Close()
			if err == nil || err == unix.EEXIST {
				fmt.Fprintf(out, "[loader] loaded module %s\n", name)
				progress = true
			} else {
				failed = append(failed, name)
			}
		}
		if !progress {
			for _, name := range failed {
				fmt.Fprintf(out, "[loader] load %s: unresolved deps\n", name)
			}
			return
		}
		pending = failed
	}
}

func bringUpNetwork(out io.Writer) {
	loadModules(out)
	if lo, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(lo)
	}
	// PCI/virtio probing is async; the NIC may not be enumerated yet at PID 1.
	// Poll for a non-loopback link for a few seconds.
	var eth netlink.Link
	deadline := time.Now().Add(12 * time.Second)
	for {
		links, _ := netlink.LinkList()
		if eth = primaryEth(links); eth != nil {
			break
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(out, "[loader] net: no non-loopback link after 12s; links seen:")
			for _, l := range links {
				fmt.Fprintf(out, "[loader] link: %s type=%s encap=%s\n", l.Attrs().Name, l.Type(), l.Attrs().EncapType)
			}
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	name := eth.Attrs().Name
	if err := netlink.LinkSetUp(eth); err != nil {
		fmt.Fprintf(out, "[loader] net: link up %s: %v\n", name, err)
		return
	}
	cli, err := nclient4.New(name)
	if err != nil {
		fmt.Fprintf(out, "[loader] net: dhcp client on %s: %v\n", name, err)
		return
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	lease, err := cli.Request(ctx)
	if err != nil {
		fmt.Fprintf(out, "[loader] net: dhcp on %s: %v\n", name, err)
		return
	}
	ack := lease.ACK
	ip := ack.YourIPAddr
	mask := ack.SubnetMask()
	if mask == nil {
		mask = net.CIDRMask(32, 32)
	}
	if err := netlink.AddrAdd(eth, &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: mask}}); err != nil {
		fmt.Fprintf(out, "[loader] net: addr add: %v\n", err)
	}
	var gw net.IP
	if rs := ack.Router(); len(rs) > 0 {
		gw = rs[0]
	}
	if gw != nil {
		idx := eth.Attrs().Index
		_ = netlink.RouteAdd(&netlink.Route{LinkIndex: idx, Dst: &net.IPNet{IP: gw, Mask: net.CIDRMask(32, 32)}, Scope: netlink.SCOPE_LINK})
		_ = netlink.RouteReplace(&netlink.Route{Gw: gw})
	}
	// Write /etc/resolv.conf from the DHCP DNS option; without it Go's resolver
	// defaults to ::1:53 (no resolver in the minimal image) and all name lookups
	// fail — breaking the AK-cert-chain fetch and dialing the router by hostname.
	dns := ack.DNS()
	if len(dns) == 0 {
		dns = []net.IP{net.IPv4(169, 254, 169, 254)} // GCE metadata DNS fallback
	}
	_ = os.MkdirAll("/etc", 0o755)
	var rc strings.Builder
	for _, d := range dns {
		rc.WriteString("nameserver " + d.String() + "\n")
	}
	if err := os.WriteFile("/etc/resolv.conf", []byte(rc.String()), 0o644); err != nil {
		fmt.Fprintf(out, "[loader] resolv.conf: %v\n", err)
	}
	fmt.Fprintf(out, "[loader] net up: %s ip=%s gw=%s dns=%v\n", name, ip, gw, dns)
}

func primaryEth(links []netlink.Link) netlink.Link {
	for _, l := range links {
		a := l.Attrs()
		if a.Name == "lo" || a.Flags&net.FlagLoopback != 0 {
			continue
		}
		return l
	}
	return nil
}

func readPCR(idx uint32) ([]byte, error) {
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		return nil, err
	}
	defer tpm.Close()
	sel := make([]byte, 3)
	sel[idx/8] |= 1 << (idx % 8)
	resp, err := tpm2.PCRRead{PCRSelectionIn: tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: sel}},
	}}.Execute(tpm)
	if err != nil {
		return nil, err
	}
	if len(resp.PCRValues.Digests) == 0 {
		return nil, fmt.Errorf("no digest")
	}
	return resp.PCRValues.Digests[0].Buffer, nil
}

// extendPCR extends PCR idx in each allocated bank B with B(appHash), so the
// verifier can recompute the per-bank PCR from the single cross-cloud appHash
// (GCP reads the SHA-256 bank, AWS's NitroTPM doc reads SHA-384). Banks that
// aren't allocated just fail and are skipped.
func extendPCR(idx uint32, appHash []byte) error {
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		return fmt.Errorf("open tpm: %w", err)
	}
	defer tpm.Close()
	banks := []struct {
		alg tpm2.TPMAlgID
		h   func() hash.Hash
	}{
		{tpm2.TPMAlgSHA256, sha256.New},
		{tpm2.TPMAlgSHA384, sha512.New384},
	}
	extended := 0
	for _, b := range banks {
		hh := b.h()
		hh.Write(appHash)
		if _, e := (tpm2.PCRExtend{
			PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(idx), Auth: tpm2.PasswordAuth(nil)},
			Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: b.alg, Digest: hh.Sum(nil)}}},
		}).Execute(tpm); e == nil {
			extended++
		}
	}
	if extended == 0 {
		return fmt.Errorf("PCR %d extend: no banks extended", idx)
	}
	return nil
}

func mountPseudo() {
	for _, m := range []struct{ src, tgt, fs string }{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
		{"devtmpfs", "/dev", "devtmpfs"},
		{"securityfs", "/sys/kernel/security", "securityfs"},
	} {
		_ = os.MkdirAll(m.tgt, 0o555)
		_ = syscall.Mount(m.src, m.tgt, m.fs, 0, "")
	}
}

func stageSecureBootEventLog() error {
	raw, err := os.ReadFile(firmwareEventLogPath)
	if err != nil {
		return fmt.Errorf("read firmware event log: %w", err)
	}
	if len(raw) == 0 {
		return fmt.Errorf("firmware event log is empty")
	}
	if err := os.WriteFile(appEventLogPath, raw, 0o444); err != nil {
		return fmt.Errorf("stage firmware event log: %w", err)
	}
	if err := os.Chmod(appEventLogPath, 0o444); err != nil {
		return fmt.Errorf("protect staged firmware event log: %w", err)
	}
	return nil
}

func console() io.Writer {
	f, err := os.OpenFile("/dev/console", os.O_WRONLY, 0)
	if err != nil {
		return os.Stdout
	}
	return io.MultiWriter(os.Stdout, f)
}

func powerOff() {
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {}
}

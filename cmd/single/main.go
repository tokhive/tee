// Command single is the one-instance topology supervisor. Normally the loaded
// SNP bundle runs the real `tee` binary directly as ./app (cross-host mode, Hub
// and agents on a separate ordinary machine). With TOKENHIVE_SUPERVISE=1 the
// ./app is instead this binary, which keeps the WHOLE loop inside one measured
// confidential instance: the loader's root broker copy hands the attestation
// role to the real tee, while the unprivileged app copy brings up mockprovider,
// a real tee server, the Hub and a provider agent — all on loopback — and pins
// the tee's RA-TLS certificate through the same /v1/init-cert handshake as the
// cross-host flow, just against 127.0.0.1.
//
// Whatever the topology, ./svc/tee is the measured, attested process: this
// dispatcher adds no trust boundary, only process topology.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// bundleDir is where the loader extracts the measured ./app (this binary) and
// the accompanying ./svc/* and ./mtls/*. The loader execs us there, so resolve
// their absolute paths from here regardless of cwd.
const bundleDir = "/run/bundle"

var (
	simDir    string
	initToken string
	agentKey  string
	// relayKey authenticates the tee's dial-in to the Hub's TeeRelay. The Hub
	// now refuses to serve without one, so the loopback topology needs it just
	// as the cross-host one does; both sides read the same value from this
	// process, so it never leaves the instance.
	relayKey  string
	teeCert   string
	teeSvcFD3 *os.File // the app copy's attestation broker socket, re-passed to the tee server
)

func main() {
	// Under the measured loader, the same ./app is launched twice: once as the
	// root-only attestation broker (SNP_ATTEST_BROKER_SERVER=1) and once as the
	// unprivileged app. Both roles are really the tee's job, so off-supervise
	// (the default) we hand straight on to the real tee binary.
	if os.Getenv("SNP_ATTEST_BROKER_SERVER") == "1" || os.Getenv("TOKENHIVE_SUPERVISE") != "1" {
		execTee()
	}

	simDir = env("TOKENHIVE_SIM_DIR", "/tmp/tee")
	initToken = env("TEE_INIT_TOKEN", "")
	agentKey = env("TOKENHIVE_AGENT_KEY", "xhost-single-key")
	relayKey = env("TOKENHIVE_RELAY_KEY", "xhost-relay-key")
	teeCert = filepath.Join(simDir, "tee-cert.pem")
	if err := os.MkdirAll(simDir, 0o755); err != nil {
		logf("mkdir simdir: %v", err)
		os.Exit(1)
	}
	// The app copy owns sockFD 3 to the root broker; hand it to the tee server
	// child so attestation stays with the measured broker.
	teeSvcFD3 = os.NewFile(3, "snp-attestation-client")

	if err := supervise(); err != nil {
		logf("supervise: %v", err)
		os.Exit(1)
	}
}

// execTee replaces this process with the real, measured tee binary so that one
// bundle serves both topologies and this dispatcher never doubles as an
// attested process itself.
func execTee() {
	b := filepath.Join(bundleDir, "svc", "tee")
	if _, err := os.Stat(b); err == nil { // supervise bundle: explicit svc/tee
		runAndExit(b, os.Args[1:]...)
	}
	// Classic layout: ./app is the tee itself.
	runAndExit(filepath.Join(bundleDir, "app"), os.Args[1:]...)
}

func runAndExit(bin string, args ...string) {
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	logf("tee %s exited: %v", bin, err)
	os.Exit(1)
}

func supervise() error {
	start(mpCmd(18080))
	start(teeCmd())
	if initToken == "" {
		return fmt.Errorf("TOKENHIVE_SUPERVISE requires TEE_INIT_TOKEN")
	}
	appHash := os.Getenv("SNP_APP_HASH")
	if appHash == "" {
		return fmt.Errorf("SNP_APP_HASH not set by loader; cannot pin the attested app identity")
	}
	fetch := time.Now()
	for {
		if err := fetchTEECert(); err == nil {
			break
		} else if time.Since(fetch) > 4*time.Minute {
			return fmt.Errorf("tee RA-TLS cert never appeared: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	start(hubCmd(appHash))
	start(agentCmd())
	// Self-test: once hub + agent are up, drive ONE real chat request over the
	// loopback so the single-instance run proves the whole business loop
	// (hub -> tee mTLS -> relay -> agent -> mockprovider) actually answers,
	// not just that every process happened to start.
	go selfTest()
	waitAll()
	return nil
}

// selfTest polls the loopback hub until it answers, then sends one
// chat/completions request and logs the HTTP status + response head. The
// result stays visible in the loader console, which is the only observability
// channel of a confidential instance (no sshd).
func selfTest() {
	body := `{"model":"sim-mock-0.5b","messages":[{"role":"user","content":"hello"}]}`
	client := &http.Client{Timeout: 60 * time.Second}
	for {
		resp, err := client.Post("http://127.0.0.1:18085/v1/chat/completions",
			"application/json", strings.NewReader(body))
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			logf("self-test: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
			return
		}
		logf("self-test: hub not ready yet (%v); retrying", err)
		time.Sleep(5 * time.Second)
	}
}

func waitAll() {
	// Restart-on-exit keeps the loop up if a child dies; it runs forever.
	for {
		time.Sleep(60 * time.Second)
	}
}

// ---- child builders ---------------------------------------------------------

func teeCmd() *exec.Cmd {
	c := cmd("svc/tee",
		"-addr", "127.0.0.1:18090",
		"-relay", "ws://127.0.0.1:18085/v1/relay",
		"-relay-key", relayKey,
		"-platform", "sevsnp",
		"-mtls",
		"-mtls-client-ca", filepath.Join(bundleDir, "mtls", "hub-ca.pem"),
		"-init-addr", "127.0.0.1:18091",
		"-init-token", initToken,
		"-seq", filepath.Join(simDir, "seqstore.json"),
	)
	c.Env = withEnv("SNP_ATTEST_BROKER_FD=3", "TOKENHIVE_SIM_DIR="+simDir)
	c.ExtraFiles = []*os.File{teeSvcFD3} // -> child fd 3
	return c
}

func mpCmd(port int) *exec.Cmd {
	// Serve the fixed mock-provider identity from the bundle (mp-ca.pem is also
	// what the tee trusts via TEE_CA), republishing its CA at <simdir>/ca.pem
	// for the agent's model-list fetch.
	c := cmd("svc/mockprovider", "-addr", fmt.Sprintf("127.0.0.1:%d", port),
		"-tls", "-stats-addr", "127.0.0.1:18081",
		"-ca", filepath.Join(bundleDir, "mtls", "mp-ca.pem"),
		"-cert", filepath.Join(bundleDir, "mtls", "mp-cert.pem"),
		"-key", filepath.Join(bundleDir, "mtls", "mp-key.pem"))
	c.Env = withEnv("TOKENHIVE_SIM_DIR=" + simDir)
	return c
}

func hubCmd(appHash string) *exec.Cmd {
	c := cmd("svc/hub",
		"-serve", "0.0.0.0:18085",
		// Per-provider keys: the agent below dials in as openai-sim, so the gate
		// binds that provider to this key. The Hub refuses to start without both
		// this map and the relay key, matching the cross-host deployment's gate.
		"-agent-keys", "openai-sim=" + agentKey,
		"-relay-key", relayKey,
		"-host", "127.0.0.1:18080",
		"-model", "sim-mock-0.5b",
		"-tee", "https://127.0.0.1:18090",
		"-mtls-ca", teeCert,
		"-mtls-cert", filepath.Join(bundleDir, "mtls", "hub-cert.pem"),
		"-mtls-key", filepath.Join(bundleDir, "mtls", "hub-key.pem"),
		// Real SNP receipts: the hub must trust the platform and pin the exact
		// measured bundle (the loader exports its digest as SNP_APP_HASH).
		"-allowed-platforms", "aws-sev-snp",
		"-expected-app", "snp-app:"+appHash,
	)
	c.Env = withEnv("TOKENHIVE_SIM_DIR=" + simDir)
	return c
}

func agentCmd() *exec.Cmd {
	c := cmd("svc/agent",
		"-hub", "ws://127.0.0.1:18085/v1/agent",
		"-key", agentKey,
		"-provider", "openai-sim",
		"-token", "sk-xhost-secret",
		"-targets", "127.0.0.1:18080",
		"-ca", filepath.Join(simDir, "ca.pem"),
	)
	c.Env = withEnv("TOKENHIVE_SIM_DIR=" + simDir)
	return c
}

// ---- plumbing ---------------------------------------------------------------

func cmd(bin string, args ...string) *exec.Cmd {
	c := exec.Command(filepath.Join(bundleDir, bin), args...)
	c.Stdout = &logWriter{name: filepath.Base(bin)}
	c.Stderr = c.Stdout
	return c
}

func start(c *exec.Cmd) {
	go func() {
		logf("start %s", strings.Join(c.Args, " "))
		if err := c.Run(); err != nil {
			logf("%s exited: %v", c.Args[0], err)
		}
	}()
}

// fetchTEECert pulls the tee's RA-TLS leaf over the same one-shot bootstrap as
// the cross-host flow and pins it for the Hub's -mtls-ca.
func fetchTEECert() error {
	httpc := &http.Client{Timeout: 3 * time.Second}
	resp, err := httpc.Get(fmt.Sprintf("http://127.0.0.1:18091/v1/init-cert?token=%s", initToken))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("init-cert HTTP %d", resp.StatusCode)
	}
	pem, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return os.WriteFile(teeCert, pem, 0o644)
}

type logWriter struct{ name string }

func (w *logWriter) Write(p []byte) (int, error) {
	logf("[%s] %s", w.name, strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func withEnv(kv ...string) []string {
	have := map[string]bool{}
	for _, e := range kv {
		have[strings.SplitN(e, "=", 2)[0]] = true
	}
	var out []string
	for _, e := range os.Environ() {
		if k := strings.SplitN(e, "=", 2)[0]; !have[k] {
			out = append(out, e)
		}
	}
	return append(out, kv...)
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, time.Now().Format("15:04:05")+" [single] "+format+"\n", a...)
}
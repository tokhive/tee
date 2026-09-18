// Command single is the one-instance topology supervisor. Normally the loaded
// SNP bundle runs the real `tee` binary directly as ./app (cross-host mode, Hub
// and agents on a separate ordinary machine). With TOKENHIVE_SUPERVISE=1 the
// ./app is instead this binary, which keeps the WHOLE loop inside one measured
// confidential instance: the loader's root broker copy hands the attestation
// role to the real tee, while the unprivileged app copy brings up mockprovider,
// a real tee server, the Hub and a provider agent — all on loopback. The Hub
// authenticates the tee by attestation, so the instance's epoch rotation never
// invalidates anything the supervisor set up at startup.
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

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
)

// bundleDir is where the loader extracts the measured ./app (this binary) and
// the accompanying ./svc/* and ./mtls/*. The loader execs us there, so resolve
// their absolute paths from here regardless of cwd.
const bundleDir = "/run/bundle"

// bundlePolicyArgs returns the -policy-dir flag pair only when the measured
// bundle actually carries a ./policy directory. pack.sh stages the deployment
// whitelist there, so pointing tee and hub at it means both read the whitelist
// from inside the measured tar (whose digest is SNP_APP_HASH) instead of a
// path that could be changed under the running enclave. The whitelist is fixed
// for the life of the deployment, so changing it is a rebuild — which moves the
// attestation fingerprint rather than silently widening what the enclave
// accepts.
//
// The children resolve this themselves too (see shared.ResolvePolicyDir); the
// supervisor passes it explicitly so a failure to resolve shows up in the
// spawned command line rather than only in the child's log. It does not require
// the whitelist here: when the bundle lacks one, the sevsnp TEE child refuses
// to serve on its own, which is where the rule belongs.
func bundlePolicyArgs() []string {
	if d, err := shared.ResolvePolicyDir("", false); err == nil && d != "" {
		return []string{"-policy-dir", d}
	}
	return nil
}

var (
	simDir    string
	initToken string
	agentKey  string
	// relayKey authenticates the tee's dial-in to the Hub's TeeRelay. The Hub
	// now refuses to serve without one, so the loopback topology needs it just
	// as the cross-host one does; both sides read the same value from this
	// process, so it never leaves the instance.
	relayKey string
	// teeCert is the path the tee child publishes its RA-TLS leaf to
	// (shared.MTLSServerCertPath under the same sim dir). The supervisor only
	// watches it for readiness — the Hub trusts the attestation in the leaf, not
	// the leaf itself.
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
	// Clear any leaf a previous tee left at this path before spawning this
	// run's, because waitForTEECert treats the file's presence as "the tee can
	// serve". On a fresh boot the state directory is empty and this is a no-op;
	// a supervisor restarted within one boot would otherwise find the old file
	// instantly and let the Hub dial a listener that has not come up yet. The
	// child writes this path itself, synchronously, before it starts serving.
	if err := os.Remove(teeCert); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear stale %s: %w", teeCert, err)
	}
	start(teeCmd())
	if initToken == "" {
		return fmt.Errorf("TOKENHIVE_SUPERVISE requires TEE_INIT_TOKEN")
	}
	appHash := os.Getenv("SNP_APP_HASH")
	if appHash == "" {
		return fmt.Errorf("SNP_APP_HASH not set by loader; cannot pin the attested app identity")
	}
	// Ordering, not trust: the Hub must not dial the tee before the tee serves.
	// The startup handshake that used to carry both is gone — the Hub no longer
	// pins the tee's certificate, it verifies the SEV-SNP evidence inside it
	// (see hubCmd), so there is nothing to fetch. What remains is the wait.
	if err := waitForTEECert(); err != nil {
		return err
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
	// Park forever so the dispatcher outlives the children it started. It does
	// NOT restart them: start() runs each child once and only logs its exit, so a
	// child that dies stays dead while this loop keeps the process (and the
	// loader's view of the instance) up. There is no supervision here — if the
	// loop-back topology needs a crashed child brought back, that has to be
	// built, not assumed.
	for {
		time.Sleep(60 * time.Second)
	}
}

// ---- child builders ---------------------------------------------------------

func teeCmd() *exec.Cmd {
	c := cmd("svc/tee",
		append([]string{
			"-addr", "127.0.0.1:18090",
			"-relay", "ws://127.0.0.1:18085/v1/relay",
			"-relay-key", relayKey,
			"-platform", "sevsnp",
			"-mtls",
			"-mtls-client-ca", filepath.Join(bundleDir, "mtls", "hub-ca.pem"),
			"-init-addr", "127.0.0.1:18091",
			"-init-token", initToken,
			"-seq", filepath.Join(simDir, "seqstore.json"),
		}, bundlePolicyArgs()...)...)
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
		append([]string{
			"-serve", "0.0.0.0:18085",
			// Per-provider keys: the agent below dials in as openai-sim, so the gate
			// binds that provider to this key. The Hub refuses to start without both
			// this map and the relay key, matching the cross-host deployment's gate.
			"-agent-keys", "openai-sim=" + agentKey,
			"-relay-key", relayKey,
			"-host", "127.0.0.1:18080",
			"-model", "sim-mock-0.5b",
			"-tee", "https://127.0.0.1:18090",
			// Attestation, not a pinned certificate: this instance rotates its
			// attested epoch for as long as it runs, so a leaf handed to the Hub
			// at startup stops matching within one refresh interval. Verifying the
			// evidence the leaf carries is the only statement that survives the
			// rotation — and it is just as strong, since the evidence is bound to
			// that leaf's own key and narrowed to the measured bundle below.
			"-tee-verify", "attestation",
			"-mtls-cert", filepath.Join(bundleDir, "mtls", "hub-cert.pem"),
			"-mtls-key", filepath.Join(bundleDir, "mtls", "hub-key.pem"),
			// Real SNP receipts: the hub must trust the platform and pin the exact
			// measured bundle (the loader exports its digest as SNP_APP_HASH).
			"-allowed-platforms", "aws-sev-snp",
			"-expected-app", "snp-app:" + appHash,
		}, bundlePolicyArgs()...)...)
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

// waitForTEECert blocks until the tee child has published its RA-TLS leaf. The
// tee writes that file itself (shared.WriteTEECert) immediately before it starts
// serving, and rewrites it on every epoch rotation, so its presence is the
// signal that the mTLS listener is about to answer.
//
// This replaced an HTTP fetch of the same bytes over the bootstrap listener: the
// supervisor used to pull the leaf through /v1/init-cert so it could hand the
// Hub a pin. Both the fetch and the pin are gone (the Hub verifies attestation),
// and the tee had been writing this very path all along — so the handshake was
// reading back a file it already had.
func waitForTEECert() error {
	deadline := time.Now().Add(4 * time.Minute)
	for {
		if fi, err := os.Stat(teeCert); err == nil && fi.Size() > 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("tee RA-TLS cert never appeared at %s", teeCert)
		}
		time.Sleep(2 * time.Second)
	}
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

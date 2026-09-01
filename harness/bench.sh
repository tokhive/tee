#!/bin/bash
# TokenHive S5 performance benchmark.
#
# Starts the same real components the S4 harness uses (mock provider over real
# TLS, SOCKS5 Provider Agent, simulated TEE on the genuine tee.Service) and runs
# tokenhive/cmd/bench in two configurations:
#
#   direct  -> client -> provider            (baseline, no TEE/Agent)
#   tee     -> client -> TEE -> Agent -> provider
#
# bench reports the four §9 acceptance metrics and gates the hard ones:
#   proof volume   < 2 KB        (sim adapter must fit; non-negotiable)
#   receipt p95    < 5 ms
#   TTFT overhead  < 1%          (relative; needs a realistic baseline RTT)
#   throughput     < 3%
#
# On localhost the baseline latency is near zero, so the relative TTFT target
# is not measurable directly; bench reports the absolute TEE delta and gates on
# a localhost-friendly delta instead. Pass -baseline-rtt to evaluate the §9
# relative TTFT target (e.g. the latency a real provider would add).
#
# Usage:
#   bash tokenhive/harness/bench.sh
#   bash tokenhive/harness/bench.sh -baseline-rtt 50ms

set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="$SCRIPT_DIR/bin"
SIM="$REPO/.sim"

cd "$REPO" || exit 1

BASELINE_RTT=""
while [ $# -gt 0 ]; do
  case "$1" in
    -baseline-rtt) BASELINE_RTT="$2"; shift 2 ;;
    *) shift ;;
  esac
done

# kill stale simulation processes from an interrupted prior run
pkill -f "$BIN/" 2>/dev/null
pkill -f "tokenhive/cmd" 2>/dev/null
sleep 0.3

echo "==> repo: $REPO"
mkdir -p "$BIN"
echo "==> building: mockprovider agent tee bench"
for pkg in mockprovider agent tee bench; do
  go build -o "$BIN/$pkg" "./tokenhive/cmd/$pkg" || { echo "build failed for $pkg"; exit 1; }
done

rm -rf "$SIM"
mkdir -p "$SIM"

wait_for_port() {
  local host="$1" port="$2" tries=50
  while ! (echo > "/dev/tcp/$host/$port") 2>/dev/null; do
    tries=$((tries-1))
    [ "$tries" -le 0 ] && { echo "  !! timeout waiting $host:$port"; return 1; }
    sleep 0.2
  done
}

MP_PORT=18080
AGENT_PORT=18092
TEE_PORT=18090

echo "==> starting mockprovider (TLS) on :$MP_PORT"
"$BIN/mockprovider" -addr "127.0.0.1:$MP_PORT" -tls > "$SIM/mockprovider.log" 2>&1 &
MP_PID=$!
wait_for_port 127.0.0.1 "$MP_PORT"

echo "==> starting provider agent on :$AGENT_PORT (allowlist -> provider)"
"$BIN/agent" -addr "127.0.0.1:$AGENT_PORT" -targets "127.0.0.1:$MP_PORT" > "$SIM/agent.log" 2>&1 &
AGENT_PID=$!
wait_for_port 127.0.0.1 "$AGENT_PORT"

echo "==> starting simulated TEE on :$TEE_PORT (egress via agent)"
"$BIN/tee" -addr "127.0.0.1:$TEE_PORT" -agent "127.0.0.1:$AGENT_PORT" -seq "$SIM/seqstore.json" > "$SIM/tee.log" 2>&1 &
TEE_PID=$!
wait_for_port 127.0.0.1 "$TEE_PORT"

RTT_ARG=""
if [ -n "$BASELINE_RTT" ]; then RTT_ARG="-baseline-rtt $BASELINE_RTT"; fi

FAIL=0

section() { echo; echo "=================================================="; echo "==> $1"; echo "=================================================="; }

# --- latency scenario: small interactive-style response -------------------
section "S5a. latency (normal small response, n=200)"
"$BIN/bench" -mode both -query "" -max 1048576 -n 200 $RTT_ARG || FAIL=1

# --- throughput scenario: large response, both modes capped at 1 MiB -------
section "S5b. throughput (fault=big, capped at 1 MiB, n=20)"
"$BIN/bench" -mode both -query "fault=big" -max 1048576 -n 20 $RTT_ARG || FAIL=1

echo
echo "==> stopping services"
kill "$MP_PID" "$AGENT_PID" "$TEE_PID" 2>/dev/null
pkill -f "$BIN/" 2>/dev/null

if [ "$FAIL" -eq 0 ]; then
  echo "==> S5 benchmark: GATE pass"
  exit 0
else
  echo "==> S5 benchmark: GATE fail"
  exit 1
fi

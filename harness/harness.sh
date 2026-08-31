#!/bin/bash
# TokenHive local simulation harness.
#
# Builds the four simulation binaries, starts the mock provider and the
# simulated TEE, and walks the scenario matrix end to end:
#   normal flow            -> seq 1..5, verified receipts
#   policy denial          -> 403, no receipt (credential never touched)
#   provider 401 / 429     -> receipt with CompletionFailed
#   provider truncate      -> receipt with CompletionTruncated
#   TEE restart            -> ProviderSeq keeps climbing (cross-restart survival)
#   ProviderSeq gap        -> Hub hides one record, audit detects the gap
#
# Nothing here talks to a real model or a real enclave.

set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="$SCRIPT_DIR/bin"
SIM="$REPO/.sim"

cd "$REPO" || exit 1

echo "==> repo: $REPO"

# --- kill any stale simulation processes from an interrupted prior run -----
# (a leftover faketee would still hold :18090 and serve an old policy/seqstore)
pkill -f "$BIN/" 2>/dev/null
pkill -f "tokenhive/cmd" 2>/dev/null
sleep 0.3

# --- build ---------------------------------------------------------------
echo "==> building simulation binaries"
mkdir -p "$BIN"
for pkg in mockprovider faketee hub verify tee agent; do
  echo "    building $pkg"
  go build -o "$BIN/$pkg" "./tokenhive/cmd/$pkg" || { echo "build failed for $pkg"; exit 1; }
done

# --- fresh state ---------------------------------------------------------
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
TEE_PORT=18090

# --- start mock provider (real TLS via generated test CA) -----------------
echo "==> starting mockprovider (TLS) on :$MP_PORT"
"$BIN/mockprovider" -addr "127.0.0.1:$MP_PORT" -tls > "$SIM/mockprovider.log" 2>&1 &
MP_PID=$!
wait_for_port 127.0.0.1 "$MP_PORT"

# --- start simulated TEE -------------------------------------------------
echo "==> starting faketee (sim TEE) on :$TEE_PORT"
"$BIN/faketee" -addr "127.0.0.1:$TEE_PORT" -seq "$SIM/seqstore.json" > "$SIM/faketee.log" 2>&1 &
TEE_PID=$!
wait_for_port 127.0.0.1 "$TEE_PORT"

section() { echo; echo "=================================================="; echo "==> $1"; echo "=================================================="; }

# --- 1. normal flow ------------------------------------------------------
section "1. normal flow (5 requests)"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -n 5

# --- 2. policy denial (wrong host) ---------------------------------------
section "2. policy denial: Hub sends disallowed host 1.2.3.4:18080"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -host "1.2.3.4:18080" || true

# --- 3/4/5. provider faults ---------------------------------------------
section "3. provider returns 401 (CompletionFailed)"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -query "fault=401" || true

section "4. provider returns 429 (CompletionFailed)"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -query "fault=429" || true

section "5. provider drops connection mid-stream (CompletionTruncated)"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -query "fault=truncate" || true

# --- 6. cross-restart ProviderSeq survival -------------------------------
section "6. restart faketee; ProviderSeq must keep climbing"
echo "    (killing faketee pid $TEE_PID)"
kill "$TEE_PID" 2>/dev/null; wait "$TEE_PID" 2>/dev/null
"$BIN/faketee" -addr "127.0.0.1:$TEE_PORT" -seq "$SIM/seqstore.json" > "$SIM/faketee2.log" 2>&1 &
TEE_PID=$!
wait_for_port 127.0.0.1 "$TEE_PORT"
echo "    sending 1 request after restart; expect seq to continue, not reset:"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -n 1

# --- 7. ProviderSeq gap detection ---------------------------------------
section "7. ProviderSeq gap: Hub hides one record, audit must catch it"
echo "    (reset store + restart faketee for an isolated demo)"
rm -rf "$SIM/receipts" "$SIM/seqstore.json"
kill "$TEE_PID" 2>/dev/null; wait "$TEE_PID" 2>/dev/null
"$BIN/faketee" -addr "127.0.0.1:$TEE_PORT" -seq "$SIM/seqstore.json" > "$SIM/faketee3.log" 2>&1 &
TEE_PID=$!
wait_for_port 127.0.0.1 "$TEE_PORT"
echo "    sending 3, withholding the 2nd receipt (expect stored seqs {1,3}):"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -n 3 -drop 2
echo
echo "    --> auditing the receipt store:"
"$BIN/hub" -audit || "$BIN/verify" -provider openai-sim

# --- cleanup -------------------------------------------------------------
echo
echo "==> stopping services"
kill "$MP_PID" "$TEE_PID" 2>/dev/null
echo "==> done. Logs in $SIM/"

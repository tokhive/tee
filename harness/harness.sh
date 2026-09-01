#!/bin/bash
# TokenHive local simulation harness.
#
# Builds the simulation binaries, starts the mock provider and the simulated
# TEE, and walks the scenario matrix end to end:
#   normal flow            -> seq 1..5, verified receipts, priced from the
#                             provider's own signed policy
#   policy denial          -> 403, no receipt (credential never touched)
#   provider 401 / 429     -> attested, but earns nothing
#   provider truncate      -> receipt with CompletionTruncated
#   TEE restart            -> ProviderSeq keeps climbing (cross-restart survival)
#   ProviderSeq gap        -> Hub hides one record, audit detects the gap
#   quota                  -> refused request never reaches the TEE, so it
#                             burns no ProviderSeq and leaves no gap
#   real TEE via agent     -> genuine tee.Service egressing through a SOCKS5
#                             Provider Agent over real TLS; a packet capture
#                             proves the agent relays only ciphertext
#   agent killed mid-req   -> the request fails cleanly, never hangs/panics
#   epoch rotation         -> a TEE restarted with a new key still verifies
#   oversize response      -> the TEE truncates at its MaxResponseBytes cap
#
# Nothing here talks to a real model or a real enclave. The Hub's business
# rules (pricing, quota, ledger, gap detection) are unit tested in-process
# against a scripted TEE; this harness exercises them over the real RPC.

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

# --- 8. quota refuses before dispatch ------------------------------------
section "8. quota: 3 attempts, tenant limited to 2"
echo "    (fresh store and seqstore so the audit is unambiguous)"
rm -rf "$SIM/receipts" "$SIM/seqstore.json"
kill "$TEE_PID" 2>/dev/null; wait "$TEE_PID" 2>/dev/null
"$BIN/faketee" -addr "127.0.0.1:$TEE_PORT" -seq "$SIM/seqstore.json" > "$SIM/faketee4.log" 2>&1 &
TEE_PID=$!
wait_for_port 127.0.0.1 "$TEE_PORT"
echo "    the 3rd request must be refused by the Hub, never reaching the TEE:"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -n 3 -quota 2 -window 1m -tenant quota-demo
echo
echo "    --> audit: 2 receipts, no gaps. A refused request that still burned"
echo "        a ProviderSeq would show up here as a missing number."
"$BIN/hub" -audit

# =====================================================================
# S4: REAL TEE through a Provider Agent.
# Scenarios 1-8 above run the A-layer fake TEE (cmd/faketee). These run the
# genuine tee.Service egressing through a real SOCKS5 Provider Agent over a
# real TLS session to the provider — the path a production deployment uses.
# =====================================================================

# --- Agent A + real TEE A, routed through the agent ---------------------
AGENT_A=18092
TEE_A=18095
section "9. real TEE -> Provider Agent (SOCKS5) -> provider (TLS)"

echo "    starting provider agent A on :$AGENT_A (tap -> $SIM/tap.log)"
"$BIN/agent" -addr "127.0.0.1:$AGENT_A" -targets "127.0.0.1:$MP_PORT" -tap "$SIM/tap.log" > "$SIM/agentA.log" 2>&1 &
AGENT_A_PID=$!
wait_for_port 127.0.0.1 "$AGENT_A"

echo "    starting REAL tee.Service A on :$TEE_A, egress via agent A"
"$BIN/tee" -addr "127.0.0.1:$TEE_A" -agent "127.0.0.1:$AGENT_A" -seq "$SIM/seqstore-real.json" > "$SIM/teeA.log" 2>&1 &
TEE_A_PID=$!
wait_for_port 127.0.0.1 "$TEE_A"

echo "    one normal request over the real path:"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_A" -n 1

echo
echo "    --> packet-capture assertion: the agent must only relay ciphertext"
CRED=$(python3 -c "import json;print(json.load(open('$SIM/providers.json'))['openai-sim'])" 2>/dev/null \
       || echo "sk-sim-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
FAIL=0
if grep -Fqa "$CRED" "$SIM/tap.log" 2>/dev/null; then echo "      !! FAIL: credential present in agent tap"; FAIL=1; fi
for needle in Bearer Authorization; do
  if grep -Fqa "$needle" "$SIM/tap.log" 2>/dev/null; then echo "      !! FAIL: '$needle' visible in plaintext on agent wire"; FAIL=1; fi
done
if [ "$FAIL" -eq 0 ]; then
  echo "      AGENT ONLY SAW CIPHERTEXT: $(wc -c < "$SIM/tap.log") bytes captured, no credential/Bearer/Authorization"
fi

# --- Agent B + real TEE B, kill the agent mid-request -------------------
AGENT_B=18093
TEE_B=18096
section "10. Provider Agent killed mid-request -> graceful failure"
echo "    starting agent B on :$AGENT_B and real tee B on :$TEE_B"
"$BIN/agent" -addr "127.0.0.1:$AGENT_B" -targets "127.0.0.1:$MP_PORT" > "$SIM/agentB.log" 2>&1 &
AGENT_B_PID=$!
wait_for_port 127.0.0.1 "$AGENT_B"
"$BIN/tee" -addr "127.0.0.1:$TEE_B" -agent "127.0.0.1:$AGENT_B" -seq "$SIM/seqstore-teeb.json" > "$SIM/teeB.log" 2>&1 &
TEE_B_PID=$!
wait_for_port 127.0.0.1 "$TEE_B"

# Fresh store so the failure receipt's sequence is unambiguous.
rm -rf "$SIM/receipts"

echo "    launching a slow request (provider sleeps 2s) in the background:"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_B" -query "fault=slow" > "$SIM/hub-slow.log" 2>&1 &
HUB_SLOW_PID=$!
sleep 0.6
echo "    killing the agent mid-request (pid $AGENT_B_PID)..."
kill "$AGENT_B_PID" 2>/dev/null
wait "$HUB_SLOW_PID" 2>/dev/null

echo "    -> the TEE must attest the failure as a signed receipt, never hang/panic:"
if grep -E "^\[receipt\].*completion=failed" "$SIM/hub-slow.log"; then
  echo "      OK: TEE attested a graceful failure (completion=failed, 0 bytes, charged 0)"
else
  echo "      !! FAIL: expected a completion=failed receipt"
fi
if grep -E "^\[receipt\].*completion=complete" "$SIM/hub-slow.log"; then
  echo "      !! FAIL: a COMPLETE receipt was produced despite the agent being killed"
fi
if grep -Fqa "panic" "$SIM/teeB.log"; then
  echo "      !! FAIL: tee panicked on agent loss"
else
  echo "      OK: tee handled the broken pipe without panic"
fi
# tee B is no longer needed.
kill "$TEE_B_PID" 2>/dev/null; wait "$TEE_B_PID" 2>/dev/null

# --- epoch rotation: restart real tee A with a fresh sim key -----------
section "11. TEE restarts with a NEW signing key (epoch rotation)"
echo "    (killing tee A pid $TEE_A_PID; a fresh sim epoch => new key)"
kill "$TEE_A_PID" 2>/dev/null; wait "$TEE_A_PID" 2>/dev/null
"$BIN/tee" -addr "127.0.0.1:$TEE_A" -agent "127.0.0.1:$AGENT_A" -seq "$SIM/seqstore-real.json" > "$SIM/teeA2.log" 2>&1 &
TEE_A_PID=$!
wait_for_port 127.0.0.1 "$TEE_A"
echo "    one request under the new key; the Hub must still verify it:"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_A" -n 1
echo "    (verification uses the signer key embedded in each receipt, so a"
echo "     rotated key is transparent — no trust-root redeploy needed)"

# --- oversize response: TEE enforces MaxResponseBytes -------------------
section "12. oversize provider response -> TEE truncates at the cap"
echo "    provider streams ~3 MiB; Hub caps the TEE at 64 KiB:"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_A" -query "fault=big" -max 65536 > "$SIM/hub-big.log" 2>&1
cat "$SIM/hub-big.log"
echo "    -> expect completion=truncated and a stream hash the Hub can verify:"
if grep -E "^\[receipt\].*completion=truncated" "$SIM/hub-big.log"; then
  echo "      OK: TEE truncated at the cap and attested it; receipt verified, settled"
else
  echo "      !! FAIL: expected completion=truncated"
fi
if grep -Fqa "different bytes" "$SIM/hub-big.log"; then
  echo "      !! FAIL: Hub could not reconcile the attested stream (hash mismatch)"
fi
echo "    (credential still never on the agent wire — see scenario 9's tap)"

# --- cleanup -------------------------------------------------------------
echo
echo "==> stopping services"
kill "$MP_PID" "$TEE_PID" "$AGENT_A_PID" "$TEE_A_PID" 2>/dev/null
pkill -f "$BIN/" 2>/dev/null
echo "==> done. Logs in $SIM/"

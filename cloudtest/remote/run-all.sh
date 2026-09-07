#!/bin/bash
# TokenHive cloudtest suite, executed ON the instance.
#
# Starts the mock provider and the real SEV-SNP TEE (mTLS, hash-only receipts),
# drives Hub requests over the attested channel, audits the receipt store, and
# bundles every artifact into ~/tokenhive-results.tar.gz for the orchestrator
# to pull back. All services stay on loopback; the security group opens only
# port 22.
set -u
cd "$HOME/tokenhive-test" || exit 1
SIM="$HOME/tokenhive-sim"
RESULTS="$HOME/tokenhive-results"
export TOKENHIVE_SIM_DIR="$SIM"
mkdir -p "$SIM" "$RESULTS"

# TEE platform: simulated (default) validates the whole pipeline on any
# instance; set TOKENHIVE_TEE_PLATFORM=sevsnp on a confidential instance to
# exercise real AWS SEV-SNP attestation instead.
TEE_PLATFORM="${TOKENHIVE_TEE_PLATFORM:-simulated}"
case "$TEE_PLATFORM" in
  sevsnp) ALLOWED_PLATFORM=aws-sev-snp ;;
  *)      ALLOWED_PLATFORM=simulated ;;
esac

echo "==> installing system dependencies"
sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends ca-certificates curl >/dev/null

echo "==> starting mockprovider (TLS) on 127.0.0.1:18080"
./mockprovider -addr 127.0.0.1:18080 -tls -stats-addr 127.0.0.1:18081 \
  >"$RESULTS/mockprovider.log" 2>&1 &
MP_PID=$!
sleep 1

echo "==> starting TEE (platform=$TEE_PLATFORM, mTLS, hash-only receipts) on 127.0.0.1:18090"
# -ca points at the mock provider's throwaway CA ($SIM/ca.pem), which
# mockprovider wrote before serving; on a production sevsnp run omit it and use
# the system trust store. -evidence=false ships hash-only receipts, which the
# Hub resolves against the shared evidence store in $SIM.
CA_ARG=""
if [ "$TEE_PLATFORM" = "simulated" ]; then CA_ARG="-ca $SIM/ca.pem"; fi
./tee -platform "$TEE_PLATFORM" -addr 127.0.0.1:18090 -mtls -evidence=false \
  $CA_ARG >"$RESULTS/tee.log" 2>&1 &
TEE_PID=$!

echo "==> waiting for the TEE's attested certificate ($SIM/tee-cert.pem)"
for _ in $(seq 1 60); do
  [ -s "$SIM/tee-cert.pem" ] && break
  kill -0 "$TEE_PID" 2>/dev/null || break
  sleep 0.5
done
if [ ! -s "$SIM/tee-cert.pem" ]; then
  echo "!! TEE did not publish tee-cert.pem; see $RESULTS/tee.log"
  tail -20 "$RESULTS/tee.log"
  kill "$MP_PID" "$TEE_PID" 2>/dev/null
  exit 1
fi

echo "==> driving 3 requests over mTLS (Hub pins the attested TEE cert)"
./hub -tee https://127.0.0.1:18090 -mtls-ca "$SIM/tee-cert.pem" \
  -credential sk-cloudtest-secret -n 3 -allowed-platforms "$ALLOWED_PLATFORM" \
  >"$RESULTS/hub.log" 2>&1 || echo "!! hub run failed (see $RESULTS/hub.log)"

echo "==> auditing the receipt store as $ALLOWED_PLATFORM"
./hub -audit -allowed-platforms "$ALLOWED_PLATFORM" >"$RESULTS/audit.log" 2>&1 \
  || echo "!! audit failed (see $RESULTS/audit.log)"

echo "==> collecting artifacts"
cp -r "$SIM/receipts" "$RESULTS/" 2>/dev/null || true
cp -r "$SIM/evidence" "$RESULTS/" 2>/dev/null || true
cp "$SIM/tee-cert.pem" "$RESULTS/" 2>/dev/null || true
cp "$SIM/tee_identity.json" "$RESULTS/" 2>/dev/null || true

kill "$MP_PID" "$TEE_PID" 2>/dev/null
wait 2>/dev/null

cd "$HOME"
tar czf tokenhive-results.tar.gz -C tokenhive-results . 2>/dev/null
echo "==> artifacts bundled at $HOME/tokenhive-results.tar.gz"

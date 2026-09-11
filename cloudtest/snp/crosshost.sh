#!/bin/bash
# Cross-host real-TEE test: a real SEV-SNP confidential instance (running the
# real `tee` binary under the two-tier loader) + an ordinary host running the
# real Hub / provider-agent / mockprovider. The whole business loop travels the
# real data planes:
#   request:  hub --mTLS(pin RA-TLS)--> tee /v1/execute
#   upstream: tee --relay WS--> hub --agent tunnel--> mockprovider
# The confidential instance has no sshd; its config is injected from EC2
# user-data by the loader, and its RA-TLS cert is fetched by the Hub over the
# one-shot TOFU bootstrap (/v1/init-cert). Tear-down is strictly by tag.
#
#   ./crosshost.sh build     certs + pack bundle(real tee)+AMI + linux binaries
#   ./crosshost.sh build-single  certs + pack supervisor bundle + AMI
#               (single-instance mode: tee+hub+agent+mockprovider all inside one
#                confidential instance, no ordinary host needed)
#   ./crosshost.sh up        launch ordinary host + confidential tee (crosshost.json)
#   ./crosshost.sh up --single  launch single-instance mode (one confidential tee)
#   ./crosshost.sh fetch     ssh to host: pull tee RA-TLS cert via /v1/init-cert
#   ./crosshost.sh deploy    scp binaries+certs, start mockprovider/hub/agent on host
#   ./crosshost.sh drive     curl a chat request via the host's Hub
#   ./crosshost.sh verify    hub/tee/agent logs + tee console attestation
#   ./crosshost.sh down      terminate BOTH instances strictly by tag
#   ./crosshost.sh down --dry-run   list what would be terminated, delete nothing
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"          # cloudtest/snp
# The host shell may carry PYTHONHOME/PYTHONPATH injected by an unrelated tool
# (e.g. a bundled Python runtime), which crashes BOTH the venv's python3 and any
# bare `python3`/aws-CLI invocation in pack.sh and snp-build.sh with
# "No module named 'encodings'". Drop them once at the top so every child step
# runs under a clean interpreter instead of needing per-call `env -u` sprinkles.
unset PYTHONHOME PYTHONPATH 2>/dev/null || true
# shellcheck source=../lib.sh
set -a; source "${HERE}/../lib.sh"; set +a
load_env
setup_logs

CLOUDTEST="${HERE}/.."
CERTS_DIR="${HERE}/.certs"
REPO_ROOT="${HERE}/../../.."            # reclaim-tee
DEPLOY_DIR="${REPO_ROOT}/deploy"
HOSTS="${CLOUDTEST}/crosshost.json"

py() { "${PY}" "$@"; }
py_cd() { ( cd "${CLOUDTEST}" && "${PY}" "$@"; ); }

host_field() { "$PY" -c "import json,sys; print(json.load(open('$HOSTS'))['host']['$1'])"; }
tee_field() { "$PY" -c "import json,sys; print(json.load(open('$HOSTS'))['tee']['$1'])"; }

# dump_tee_console <public-ip>: print the confidential instance's console output
# (the loader/attestation log) by locating it strictly through our own tags.
dump_tee_console() {
  py_cd - "$1" <<'PY'
import boto3, sys
from config import load
cfg = load()
ec2 = boto3.client("ec2", region_name=cfg.region)
for r in ec2.describe_instances(Filters=[
    {"Name": f"tag:{cfg.tag_owner}", "Values":[cfg.tag_owner_value]},
    {"Name": f"tag:{cfg.tag_user}", "Values":[cfg.user]},
])["Reservations"]:
    for i in r["Instances"]:
        if i.get("PublicIpAddress") == sys.argv[1]:
            print(ec2.get_console_output(InstanceId=i["InstanceId"]).get("Output",""))
            break
PY
}

ami_id() {
  local name="${1:-snp-tokenhive}"
  py_cd - "${name}" <<'PY'
import boto3, sys
from config import load
name = sys.argv[1]; cfg = load()
img = boto3.client("ec2", region_name=cfg.region).describe_images(
    Owners=["self"],
    Filters=[{"Name":"name","Values":[name]},{"Name":"state","Values":["available"]}],
)["Images"]
assert img, f"no AMI {name}; run ./crosshost.sh build"
img.sort(key=lambda i: i["CreationDate"])
print(img[-1]["ImageId"])
PY
}

# ensure_certs generates the Hub↔TEE and mock-provider TLS fixtures ONCE and
# reuses them across every build: the CAs are baked into each AMI's bundle at
# build time, and the same CAs must sign the client/server certs deployed
# later. Regenerating certs in one build would silently invalidate AMIs built
# earlier — their tee would reject the new hub client cert / provider cert.
ensure_certs() {
  if [ -f "${CERTS_DIR}/hub-ca.pem" ]; then
    log "reusing TLS fixtures in ${CERTS_DIR}"
    return
  fi
  mkdir -p "${CERTS_DIR}"
  ( cd "${REPO_ROOT}" && go run ./tokenhive/cloudtest/snp/gencerts "${CERTS_DIR}" )
  log "TLS fixtures -> ${CERTS_DIR}"
}

cmd_build() {
  log "step: build (certs + real-tee bundle + AMI + linux binaries)"
  ensure_certs
  ( cd "${HERE}" && SNP_HUB_CA="${CERTS_DIR}/hub-ca.pem" \
      SNP_MP_CA="${CERTS_DIR}/mp-ca.pem" SNP_MP_CERT="${CERTS_DIR}/mp-cert.pem" SNP_MP_KEY="${CERTS_DIR}/mp-key.pem" \
      ./pack.sh build )
  local bundle; bundle="${TOKENHIVE_OUT_BUNDLE:-${CLOUDTEST}/bin/tokenhive-app-bundle.tar}"
  log "bundle digest: $(cd "${HERE}" && ./pack.sh digest "${bundle}")"
  ( cd "${DEPLOY_DIR}" && SNP_EXTERNAL_BUNDLE="${bundle}" SNP_ALLOW_DIRTY=1 ./snp-build.sh t aws tokenhive )
  log "AMI registered"
  ( cd "${CLOUDTEST}" && ./run.sh build )
  log "linux binaries built"
}

cmd_build_single() {
  log "step: build (certs + supervisor bundle + AMI)"
  ensure_certs
  # The supervisor bundle needs the Hub's TLS identity (hub-cert/key) and the
  # mock provider's TLS identity (mp-cert/key), which the cross-host bundle
  # does not carry (hub and mockprovider run on the ordinary host there).
  ( cd "${HERE}" && TOKENHIVE_BUILD_SINGLE=1 \
      SNP_HUB_CA="${CERTS_DIR}/hub-ca.pem" \
      SNP_HUB_CERT="${CERTS_DIR}/hub-cert.pem" \
      SNP_HUB_KEY="${CERTS_DIR}/hub-key.pem" \
      SNP_MP_CA="${CERTS_DIR}/mp-ca.pem" \
      SNP_MP_CERT="${CERTS_DIR}/mp-cert.pem" \
      SNP_MP_KEY="${CERTS_DIR}/mp-key.pem" \
      ./pack.sh build )
  local bundle; bundle="${TOKENHIVE_OUT_BUNDLE:-${CLOUDTEST}/bin/tokenhive-app-bundle.tar}"
  log "bundle digest: $(cd "${HERE}" && ./pack.sh digest "${bundle}")"
  ( cd "${DEPLOY_DIR}" && SNP_EXTERNAL_BUNDLE="${bundle}" SNP_ALLOW_DIRTY=1 ./snp-build.sh t aws tokenhive-single )
  log "AMI snp-tokenhive-single registered"
}

cmd_up() {
  [ -f "${CERTS_DIR}/hub-ca.pem" ] || { echo "run ./crosshost.sh build first (certs)"; exit 1; }
  local a token single="" name
  [[ "${2:-}" == "--single" ]] && single="--single" && name="snp-tokenhive-single" || name="snp-tokenhive"
  a="$(ami_id "${name}")"
  log "AMI ${a}"
  # Read or mint the one-shot bootstrap token (stick to one so a re-up reuses).
  if [ -f "${CERTS_DIR}/init-token" ]; then
    token="$(cat "${CERTS_DIR}/init-token")"
  else
    token="$(openssl rand -hex 16)"
    printf '%s\n' "${token}" > "${CERTS_DIR}/init-token"
  fi
  ( cd "${HERE}" && "${PY}" crosshost.py "${a}" --token "${token}" ${single} ) | tee -a "${LOG_DIR}/run.log"
  # Pin the attested app identity for the Hub: the AMI embeds the very tar file
  # whose sha256 the loader exports as SNP_APP_HASH, so record it in state for
  # the later deploy to pass as -expected-app (single mode reads the env instead).
  local digest
  digest="$(cd "${HERE}" && ./pack.sh digest "${CLOUDTEST}/bin/tokenhive-app-bundle.tar")"
  printf '%s\n' "${digest#snp-app:}" | "${PY}" -c "
import json, sys
p = json.load(open('${HOSTS}'))
p['tee']['app_hash'] = sys.stdin.read().strip()
json.dump(p, open('${HOSTS}', 'w'), indent=2)
" && log "tee app_hash -> ${digest}"
}

cmd_fetch() {
  local tip tok out
  # Cross-host traffic goes over the PRIVATE ips: both instances share the VPC
  # subnet and the SG's group-pair rule only matches in-VPC traffic (a public-ip
  # dial from a group member is dropped by AWS). ssh to the host still uses its
  # public ip.
  tip="$(tee_field private_ip)"; tok="$(cat "${CERTS_DIR}/init-token")"
  log "step: fetch tee RA-TLS cert from bootstrap ${tip}:18091"
  out="$(remote_exec "$(host_field public_ip)" bash <<EOF
for _ in \$(seq 1 60); do
  code="\$(curl -s -o tee-cert.pem -w '%{http_code}' 'http://${tip}:18091/v1/init-cert?token=${tok}')"
  [ "\$code" = "200" ] && [ -s tee-cert.pem ] && break
  sleep 5
done
[ -s tee-cert.pem ] || { echo 'bootstrap never succeeded'; exit 1; }
wc -c tee-cert.pem
EOF
)"
  log "bootstrap -> ${out}"
  remote_pull "$(host_field public_ip)" "tee-cert.pem" "${CLOUDTEST}/snp/.certs/tee-cert.pem" >/dev/null
  log "pinned tee-cert.pem saved to ${CERTS_DIR}"
}

cmd_deploy() {
  local hip tip cert app_hash
  hip="$(host_field public_ip)"; tip="$(tee_field private_ip)"  # cross-host plane over private ips
  app_hash="$(tee_field app_hash)"
  log "step: deploy runtime to host ${hip} (tee ${tip}, app ${app_hash})"
  remote_exec "$hip" 'mkdir -p tee mtls' >/dev/null
  remote_push "$hip" "${CLOUDTEST}/bin/hub" "tee/hub" >/dev/null
  remote_push "$hip" "${CLOUDTEST}/bin/agent" "tee/agent" >/dev/null
  remote_push "$hip" "${CLOUDTEST}/bin/mockprovider" "tee/mockprovider" >/dev/null
  remote_push "$hip" "${CERTS_DIR}/hub-cert.pem" "mtls/hub-cert.pem" >/dev/null
  remote_push "$hip" "${CERTS_DIR}/hub-key.pem" "mtls/hub-key.pem" >/dev/null
  remote_push "$hip" "${CERTS_DIR}/mp-ca.pem" "mtls/mp-ca.pem" >/dev/null
  remote_push "$hip" "${CERTS_DIR}/mp-cert.pem" "mtls/mp-cert.pem" >/dev/null
  remote_push "$hip" "${CERTS_DIR}/mp-key.pem" "mtls/mp-key.pem" >/dev/null
  # tee-cert.pem (pinned) lives in CERTS_DIR after fetch
  remote_push "$hip" "${CERTS_DIR}/tee-cert.pem" "mtls/tee-cert.pem" >/dev/null

  # Per-provider agent key and the tee relay key. The Hub now requires both
  # (-agent-keys and -relay-key); the tee must present the same relay key, which
  # crosshost.py injects into the confidential instance's user-data, so both
  # scripts read the same env with the same default.
  local agent_key relay_key
  agent_key="${TOKENHIVE_AGENT_KEY:-xhost-agent-key}"
  relay_key="${TOKENHIVE_RELAY_KEY:-xhost-relay-key}"
  remote_exec "$hip" bash -s <<EOF
set -e
cd ~
export TOKENHIVE_SIM_DIR="\$HOME/tee"
killall mockprovider hub agent 2>/dev/null || true
mkdir -p "\$TOKENHIVE_SIM_DIR"
chmod 755 ./tee/hub ./tee/agent ./tee/mockprovider
./tee/mockprovider -addr 127.0.0.1:18080 -tls -stats-addr 127.0.0.1:18081 \
  -ca mtls/mp-ca.pem -cert mtls/mp-cert.pem -key mtls/mp-key.pem >tee/mp.log 2>&1 &
sleep 1
./tee/hub -serve 0.0.0.0:18085 -agent-keys 'openai-sim=${agent_key}' -relay-key '${relay_key}' \
  -host 127.0.0.1:18080 \
  -model sim-mock-0.5b -tee https://${tip}:18090 -mtls-ca mtls/tee-cert.pem \
  -mtls-cert mtls/hub-cert.pem -mtls-key mtls/hub-key.pem \
  -allowed-platforms aws-sev-snp -expected-app 'snp-app:${app_hash}' >tee/hub.log 2>&1 &
sleep 1
./tee/agent -hub ws://127.0.0.1:18085/v1/agent -key '${agent_key}' -provider openai-sim \
  -token sk-xhost-secret -targets 127.0.0.1:18080 -ca "\$TOKENHIVE_SIM_DIR/ca.pem" >tee/agent.log 2>&1 &
echo "deployed; logs under ~/tee"
EOF
  log "deployed & started on host"
  sleep 4
}

cmd_drive() {
  log "step: drive 2 chat requests via host Hub"
  remote_exec "$(host_field public_ip)" bash <<'EOF'
set -e
for i in 1 2; do
  code="$(curl -s -o resp$i.txt -w '%{http_code}' -N -X POST \
    http://127.0.0.1:18085/v1/chat/completions \
    -H 'content-type: application/json' -H 'X-TokenHive-Key: tenant-xhost' \
    -d '{"model":"sim-mock-0.5b","messages":[{"role":"user","content":"hello"}]}')"
  echo "request $i -> HTTP $code  $(head -c 120 resp$i.txt)"
done
EOF
}

cmd_verify() {
  # Single-instance mode has no separate host: the supervisor's tee+hub+agent+
  # mockprovider all log to the loader console inside the confidential instance,
  # so verify just dumps that console (which also holds the attestation proof).
  # The tee record carries mode=single from crosshost.py; a stale "host" key
  # left over from an earlier cross-host run must not flip us into host mode.
  if [[ "$(tee_field mode)" == "single" ]]; then
    log "step: verify single-instance mode (dump confidential tee console)"
    dump_tee_console "$(tee_field public_ip)"
    return
  fi
  log "step: verify logs on host"
  remote_exec "$(host_field public_ip)" bash <<'EOF'
echo "---- hub.log ----"; grep -E 'listening|relay|chat/completions' tee/hub.log | tail -8 || tail -12 tee/hub.log
echo "---- agent.log ----"; tail -6 tee/agent.log
echo "---- mockprovider.log ----"; tail -4 tee/mp.log
EOF
  log "step: dump confidential tee console (attestation proof)"
  dump_tee_console "$(tee_field public_ip)"
}

cmd_down() {
  log "step: down (strict tag deletion of all matching instances)"
  ( cd "${CLOUDTEST}" && "${PY}" delete.py "${1:-}" ) | tee -a "${LOG_DIR}/run.log"
}

case "${1:-}" in
  build)   cmd_build ;;
  build-single) cmd_build_single ;;
  up)      cmd_up "${@}" ;;
  fetch)   cmd_fetch ;;
  deploy)  cmd_deploy ;;
  drive)   cmd_drive ;;
  verify)  cmd_verify ;;
  down)    cmd_down "${2:-}" ;;
  *)
    sed -n '2,23p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 1 ;;
esac
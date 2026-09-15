#!/bin/bash
# Real SEV-SNP TEE test on AWS, fully automated: build the loader AMI from the
# TokenHive app bundle, launch a tagged confidential instance, read the
# attestation self-test back over console output, then tear everything down by
# tag. Only `delete`/`delete-infra` touch resources, and always strictly by the
# two cloudtest tags — the launch uses hosts.json, deletion never does.
#
#   ./snp.sh build           pack the bundle + build the AMI (needs deploy/.env)
#   ./snp.sh up              launch the tagged SNP instance from the AMI
#   ./snp.sh verify          poll console until SNP_TEST_RESULT; save to logs
#   ./snp.sh status          list tagged SNP instances (creates nothing)
#   ./snp.sh down            terminate SNP instances strictly by tag
#   ./snp.sh delete-infra    tear down tagged network infra (rare, destructive)
#   ./snp.sh down --dry-run  list what would be terminated, delete nothing
#
# Region/type/user come from cloudtest/.env (TOKENHIVE_REGION etc). The AMI
# name is always snp-tokenhive (built below); the instance runs with AmdSevSnp
# enabled. There is no sshd — results flow out via EC2 console output.
set -euo pipefail
# Capture snp.sh's own dir BEFORE sourcing lib.sh: that file reassigns the
# global SCRIPT_DIR to the cloudtest dir, which would silently shift every
# path derived from ${SCRIPT_DIR} below.
SNP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
set -a; source "${SNP_DIR}/../lib.sh"; set +a
load_env
setup_logs

AMI_NAME="${TOKENHIVE_SNP_AMI_NAME:-snp-tokenhive}"
CLOUDTEST_DIR="${SNP_DIR}/.."
DEPLOY_DIR="${SNP_DIR}/../../../deploy"

py() { "${PY}" "$@"; }
# Run a python heredoc from the cloudtest dir so `import config` resolves via the
# process's own cwd (sys.path[0]), independent of any host PYTHONPATH pollution.
py_cd() { ( cd "${CLOUDTEST_DIR}" && "${PY}" "$@"; ); }

ami_id() {
  py_cd - "$AMI_NAME" <<'PY'
import boto3, sys
from config import load
name = sys.argv[1]; cfg = load()
img = boto3.client("ec2", region_name=cfg.region).describe_images(
    Owners=["self"],
    Filters=[{"Name":"name","Values":[name]},{"Name":"state","Values":["available"]}],
)["Images"]
assert img, f"no AMI {name} in {cfg.region}; run ./snp.sh build"
img.sort(key=lambda i: i["CreationDate"])
print(img[-1]["ImageId"])
PY
}

cmd_build() {
  log "step: build SNP loader AMI (${AMI_NAME})"
  "${SNP_DIR}/pack.sh" build
  local bundle digest
  bundle="${TOKENHIVE_OUT_BUNDLE:-${CLOUDTEST_DIR}/bin/tokenhive-app-bundle.tar}"
  digest="$("${SNP_DIR}/pack.sh" digest "${bundle}")"
  log "app bundle digest: ${digest}"
  # Reuse the upstream two-tier loader chain: docker/qemu-img/VM-import. The
  # external bundle is adopted verbatim by snp-build.sh's SNP_EXTERNAL_BUNDLE
  # hook; role 't'/cloud 'aws' keep it on the unchanged tee_t path.
  ( cd "${DEPLOY_DIR}" && \
    SNP_EXTERNAL_BUNDLE="${bundle}" SNP_ALLOW_DIRTY=1 \
    ./snp-build.sh t aws tokenhive )
  log "AMI snp-tokenhive registered"
}

cmd_up() {
  local a; a="$(ami_id)"
  log "step: up (AMI ${a})"
  ( cd "${SNP_DIR}" && "${PY}" launch.py "${a}" ) | tee -a "${LOG_DIR}/run.log"
}

cmd_status() {
  py_cd <<'PY'
import boto3
from config import load
cfg = load()
ec2 = boto3.client("ec2", region_name=cfg.region)
for r in ec2.describe_instances(Filters=[
    {"Name": f"tag:{cfg.tag_owner}", "Values": [cfg.tag_owner_value]},
    {"Name": f"tag:{cfg.tag_user}", "Values": [cfg.user]},
])["Reservations"]:
    for i in r["Instances"]:
        print(f"{i['InstanceId']} {i['State']['Name']} {i.get('PublicIpAddress','-')}")
PY
}

cmd_verify() {
  local iid
  iid="$("${PY}" -c "import json;print(json.load(open('${HOSTS_FILE}'))['instance_id'])")"
  log "step: verify ${iid} console"
  local attempts="${1:-40}" n
  for n in $(seq 1 "${attempts}"); do
    local out; out="$(py_cd - "${iid}" <<'PY'
import boto3, sys
from config import load
cfg = load()
info = boto3.client("ec2", region_name=cfg.region).get_console_output(InstanceId=sys.argv[1])
print(info.get("Output", ""))
PY
)"
    printf '%s\n' "${out}" > "${LOG_DIR}/${iid}.console.log"
    if printf '%s' "${out}" | grep -q "SNP_TEST_RESULT matched=yes"; then
      grep "SNP_TEST_RESULT" "${LOG_DIR}/${iid}.console.log" | tail -1
      log "SNP_APP_HASH attested OK; console at ${LOG_DIR}/${iid}.console.log"
      return 0
    fi
    if printf '%s' "${out}" | grep -q "SNP_TEST_RESULT matched=no"; then
      grep "SNP_TEST_RESULT" "${LOG_DIR}/${iid}.console.log" | tail -1
      log "attestation FAILED; console at ${LOG_DIR}/${iid}.console.log"
      return 1
    fi
    sleep 15
  done
  log "timed out waiting for SNP_TEST_RESULT (see ${LOG_DIR}/${iid}.console.log)"
  return 1
}

cmd_down() {
  log "step: down (strict tag deletion)"
  ( cd "${CLOUDTEST_DIR}" && "${PY}" delete.py "${1:-}" ) | tee -a "${LOG_DIR}/run.log"
}

cmd_delete_infra() {
  log "step: delete-infra (strict tag deletion)"
  ( cd "${CLOUDTEST_DIR}" && "${PY}" delete_infra.py "${1:-}" ) | tee -a "${LOG_DIR}/run.log"
}

case "${1:-}" in
  build)      cmd_build ;;
  up)         cmd_up ;;
  status)     cmd_status ;;
  verify)     cmd_verify "${2:-}" ;;
  down)       cmd_down "${2:-}" ;;
  delete-infra) cmd_delete_infra "${2:-}" ;;
  *)
    sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 1 ;;
esac
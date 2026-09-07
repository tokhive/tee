#!/bin/bash
# TokenHive cloudtest orchestrator.
#
#   ./run.sh                create -> test -> delete (full lifecycle)
#   ./run.sh build          cross-compile the linux/amd64 binaries
#   ./run.sh create         ensure infra + launch instance + write hosts.json
#   ./run.sh test           upload, run the remote suite, pull logs back
#   ./run.sh delete         terminate instances by tag (never by hosts.json)
#   ./run.sh delete --dry-run   list matching instances, delete nothing
#   ./run.sh delete-infra    tear down tagged NETWORK infra (rare; see delete_infra.py)
#   ./run.sh delete-infra --dry-run   list infra that would be torn down
#
# Every step logs into logs/<timestamp>/; a failed test still cleans up the
# machine unless KEEP_INSTANCE=true is set.
set -u
set -o pipefail
cd "$(dirname "$0")"
. ./lib.sh

load_env
setup_logs
log "cloudtest run (user=${TOKENHIVE_USER}, region=${TOKENHIVE_REGION:-us-west-2})"

cmd="${1:-all}"

build() {
  local out="bin"
  mkdir -p "$out"
  log "building linux/amd64 binaries"
  (cd ../.. && \
   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags sevsnp -o "tokenhive/cloudtest/$out/tee" ./tokenhive/cmd/tee && \
   for pkg in hub mockprovider agent; do \
     GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "tokenhive/cloudtest/$out/$pkg" "./tokenhive/cmd/$pkg" || exit 1; \
   done) || { log "build failed"; exit 1; }
  log "built: $(ls "$out")"
}

create() {
  log "step: create"
  "$PY" create.py | tee -a "$LOG_DIR/run.log"
}

test() {
  [ -f "$HOSTS_FILE" ] || { log "no $HOSTS_FILE; run ./run.sh create first"; exit 1; }
  local ip rem
  ip="$(host_field public_ip)"
  log "step: test (instance $ip)"
  [ -x bin/tee ] || build
  log "waiting for ssh on $ip"
  wait_ssh "$ip" || { log "ssh to $ip not reachable"; exit 1; }
  rem="$(remote_exec "$ip" 'echo $HOME' | tr -d '\r')"
  [ -n "$rem" ] || { log "could not resolve remote home"; exit 1; }

  log "uploading binaries and remote script"
  remote_exec "$ip" "mkdir -p $rem/tokenhive-test"
  remote_push "$ip" bin/tee          "$rem/tokenhive-test/tee"
  remote_push "$ip" bin/hub          "$rem/tokenhive-test/hub"
  remote_push "$ip" bin/mockprovider "$rem/tokenhive-test/mockprovider"
  remote_push "$ip" bin/agent        "$rem/tokenhive-test/agent"
  remote_push "$ip" remote/run-all.sh "$rem/tokenhive-test/run-all.sh"
  remote_exec "$ip" "chmod +x $rem/tokenhive-test/*"

  log "running remote suite (platform=${TOKENHIVE_TEE_PLATFORM:-simulated})"
  remote_exec "$ip" "TOKENHIVE_TEE_PLATFORM=${TOKENHIVE_TEE_PLATFORM:-simulated} bash $rem/tokenhive-test/run-all.sh" | tee "$LOG_DIR/remote.log"

  log "pulling results back"
  remote_pull "$ip" "$rem/tokenhive-results.tar.gz" "$LOG_DIR/results.tar.gz"
  (cd "$LOG_DIR" && tar xzf results.tar.gz && rm -f results.tar.gz)
  log "results saved in $LOG_DIR"
}

delete() { # delete [--dry-run]
  log "step: delete"
  "$PY" delete.py "$@" | tee -a "$LOG_DIR/run.log"
}

delete_infra() { # delete_infra [--dry-run]
  log "step: delete-infra (NETWORK TEARDOWN — rarely used)"
  "$PY" delete_infra.py "$@" | tee -a "$LOG_DIR/run.log"
}

# Auto-cleanup for the full lifecycle: if we got far enough to launch an
# instance but the run is interrupted (Ctrl-C, crash, SSH stall) before the
# explicit delete, terminate whatever this run left running so it cannot keep
# billing. Skipped under KEEP_INSTANCE, and skipped once the explicit delete has
# already run, so we never double-terminate. Only installed for the `all` flow;
# the standalone create/test/delete subcommands keep their own semantics.
cleanup() {
  local rc=$?
  if [ "${KEEP_INSTANCE:-false}" != "true" ] && [ "${INSTANCES_DELETED:-0}" != "1" ]; then
    log "cleanup: terminating any instances this run left running"
    delete || true
  fi
  exit "$rc"
}

status=0
case "$cmd" in
  build) build; status=$? ;;
  create) create; status=$? ;;
  test) test; status=$? ;;
  delete) shift; delete "$@"; status=$? ;;
  all|"")
    trap cleanup EXIT INT TERM
    # If create fails it may still have left freshly-built scaffolding (VPC,
    # SG, key) behind; tear it down so we never leak infra, then exit.
    create || { log "CREATE FAILED (see $LOG_DIR)"; delete_infra || true; exit 1; }
    test || { log "TEST FAILED (see $LOG_DIR)"; status=1; }
    if [ "${KEEP_INSTANCE:-false}" = "true" ]; then
      log "KEEP_INSTANCE=true: skipping delete"
    else
      # Only mark deleted on success: if delete fails, cleanup retries once.
      if delete; then
        INSTANCES_DELETED=1
      else
        log "DELETE FAILED (see $LOG_DIR)"; status=1
      fi
    fi
    ;;
  delete-infra) shift; delete_infra "$@"; status=$? ;;
  *) echo "usage: $0 [build|create|test|delete|delete --dry-run|delete-infra|delete-infra --dry-run|all]"; exit 1 ;;
esac

log "done; logs in $LOG_DIR"
exit "$status"

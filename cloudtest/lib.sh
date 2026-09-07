#!/bin/bash
# Shared helpers for the cloudtest orchestrator. Sourced by run.sh.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTS_FILE="$SCRIPT_DIR/hosts.json"
LOG_DIR=""

# Prefer the project venv (created by ./setup.sh) so the Python steps have
# boto3 regardless of which interpreter is on PATH; fall back to python3.
if [ -x "$SCRIPT_DIR/.venv/bin/python3" ]; then
  PY="$SCRIPT_DIR/.venv/bin/python3"
else
  PY=python3
fi

load_env() {
  if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    . "$SCRIPT_DIR/.env"
    set +a
  fi
  if [ -z "${TOKENHIVE_USER:-}" ]; then
    echo "error: TOKENHIVE_USER is required (set it to a unique value, e.g. your name); refusing to run" >&2
    exit 1
  fi
}

setup_logs() {
  LOG_DIR="$SCRIPT_DIR/logs/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$LOG_DIR"
}

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_DIR/run.log"; }

host_field() { # host_field public_ip
  "$PY" -c "import json,sys; print(json.load(open('$HOSTS_FILE'))['$1'])"
}

wait_ssh() { # wait_ssh ip [attempts]
  local ip="$1" tries="${2:-120}"
  for _ in $(seq 1 "$tries"); do
    (echo > "/dev/tcp/$ip/22") 2>/dev/null && return 0
    sleep 2
  done
  return 1
}

SSH_OPTS=(-i "$SCRIPT_DIR/ssh-key.pem" -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR)

remote_exec() { # remote_exec ip command...
  local ip="$1"; shift
  ssh "${SSH_OPTS[@]}" "ubuntu@$ip" "$@"
}

remote_push() { # remote_push ip local remote
  scp "${SSH_OPTS[@]}" "$2" "ubuntu@$1:$3"
}

remote_pull() { # remote_pull ip remote local
  scp "${SSH_OPTS[@]}" "ubuntu@$1:$2" "$3"
}

#!/bin/bash
# Shared bash helpers for deploy scripts. Sourced, not executed.
# Provides:
#   - require_env_vars: assert all listed env vars are non-empty
#   - gcloud_retry: re-runs a gcloud command on transient network failures

# require_env_vars fails fast with a clear message if any listed var is
# empty. Use at the top of every deploy script right after sourcing
# deploy/.env so a missing var aborts before any side effects.
#
# Usage:
#   require_env_vars GCP_PROJECT GCP_ZONE ROUTER_URL ROUTER_ADMIN_TOKEN
require_env_vars() {
    local missing=()
    local v
    for v in "$@"; do
        if [[ -z "${!v:-}" ]]; then
            missing+=("${v}")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "ERROR: required env vars not set in deploy/.env:" >&2
        printf '  - %s\n' "${missing[@]}" >&2
        echo "" >&2
        echo "Copy deploy/.env.example to deploy/.env and fill in the values." >&2
        exit 1
    fi
}

# gcloud_retry runs a command, retrying on transient gcloud failures with
# exponential backoff. After a retry, "already exists" / "not found" are
# treated as success — the prior failed attempt almost certainly landed
# server-side and the client just lost the connection while reading the
# response.
#
# stdout and stderr are kept SEPARATE: the underlying command's stdout
# passes through to the caller's stdout, stderr to the caller's stderr.
# This means callers can do
#     X=$(gcloud_retry gcloud ... 2>/dev/null)
# and only capture stdout, with warnings suppressed — same as plain gcloud.
# Stderr is still captured internally for retry pattern matching.
#
# Usage:
#   gcloud_retry gcloud compute instances delete foo --quiet
#
# Tunables (env, optional):
#   GCLOUD_RETRY_MAX     — max retries (default 5)
#   GCLOUD_RETRY_DELAY   — initial backoff seconds, doubled each retry (default 1)
gcloud_retry() {
    local max="${GCLOUD_RETRY_MAX:-5}"
    local delay="${GCLOUD_RETRY_DELAY:-1}"
    local n=0
    local rc err stdout_file stderr_file
    stdout_file=$(mktemp)
    stderr_file=$(mktemp)
    # Ensure tempfiles get cleaned up on any return path.
    _gr_cleanup() { rm -f "${stdout_file}" "${stderr_file}"; }
    while true; do
        "$@" >"${stdout_file}" 2>"${stderr_file}"
        rc=$?
        err=$(cat "${stderr_file}")
        if [[ ${rc} -eq 0 ]]; then
            cat "${stdout_file}"
            [[ -n "${err}" ]] && cat "${stderr_file}" >&2
            _gr_cleanup
            return 0
        fi
        # On a retry, idempotent-success patterns mean "the failed call
        # landed; the server is in the desired state." Treat as success.
        if [[ ${n} -gt 0 ]] && echo "${err}" | grep -qiE 'already exists|not found|does not exist|was not found'; then
            cat "${stdout_file}"
            cat "${stderr_file}" >&2
            echo "[gcloud_retry] post-retry idempotent error — treating as success" >&2
            _gr_cleanup
            return 0
        fi
        # Transient-failure patterns we want to retry on.
        if [[ ${n} -lt ${max} ]] && echo "${err}" | grep -qiE 'connection (reset|aborted|refused|timed? out|broken)|ConnectionError|ConnectionResetError|ChunkedEncodingError|IncompleteRead|EOF occurred|gcloud crashed|server (closed|unavailable)|503|502|504|temporary failure|unexpected eof'; then
            cat "${stderr_file}" >&2
            n=$((n+1))
            echo "[gcloud_retry] transient failure (attempt ${n}/${max}); sleeping ${delay}s" >&2
            sleep "${delay}"
            delay=$((delay * 2))
            continue
        fi
        # Not transient or out of retries — emit both streams and propagate.
        cat "${stdout_file}"
        cat "${stderr_file}" >&2
        _gr_cleanup
        return ${rc}
    done
}

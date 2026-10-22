#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${SCRIPT_DIR}/source-commit.sh"

VALID_COMMIT="$(git -C "${REPO_ROOT}" rev-parse --verify HEAD~1)"
ABBREVIATED_COMMIT="${VALID_COMMIT:0:12}"
NON_COMMIT="$(git -C "${REPO_ROOT}" rev-parse --verify HEAD:go.mod)"
MISSING_COMMIT="$(printf '0%.0s' {1..40})"
# Same commit, upper-cased: the contract is an exact lowercase 40-hex ID, so
# this must be rejected. Built with tr rather than ${VAR^^} because /bin/bash is
# 3.2 on macOS, where that syntax is a "bad substitution" that kills the test.
UPPERCASE_COMMIT="$(tr '[:lower:]' '[:upper:]' <<< "${VALID_COMMIT}")"

snp_require_source_commit "${REPO_ROOT}" "${VALID_COMMIT}"
for invalid in --help "${ABBREVIATED_COMMIT}" "${NON_COMMIT}" "${MISSING_COMMIT}" "${UPPERCASE_COMMIT}"; do
    if snp_require_source_commit "${REPO_ROOT}" "${invalid}" 2>/dev/null; then
        echo "accepted invalid source commit: ${invalid}" >&2
        exit 1
    fi
done

TEST_DIR="$(mktemp -d)"
trap 'rm -rf "${TEST_DIR}"' EXIT
CLONE_DIR="${TEST_DIR}/source"
snp_checkout_source_commit "${REPO_ROOT}" "${VALID_COMMIT}" "${CLONE_DIR}"
[[ "$(git -C "${CLONE_DIR}" rev-parse --verify HEAD)" == "${VALID_COMMIT}" ]]
if git -C "${CLONE_DIR}" symbolic-ref -q HEAD >/dev/null; then
    echo "source checkout is not detached" >&2
    exit 1
fi

echo "SNP source commit validation tests passed"

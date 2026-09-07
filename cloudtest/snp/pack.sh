#!/bin/bash
set -euo pipefail
# Build the TokenHive SNP app bundle — the measured `./app` an SNP loader boots
# (see ../../deploy/snp-build.sh). The bundle tar's sha256 IS SNP_APP_HASH: the
# loader hashes these exact bytes into PCR 8 and re-exports the hash to the app
# process as SNP_APP_HASH. Determinism therefore matters — the same inputs must
# yield the same digest cross-host, or a verifier pins a value we can't rebuild.
#
#   ./pack.sh build [OUT]   build tokenhive-app-bundle.tar
#   ./pack.sh digest [TAR]  print the snp-app: digest log line for a bundle
#   ./pack.sh clean         remove build artifacts
#
# OUT defaults to ../bin/tokenhive-app-bundle.tar.
set -a; source ../.env 2>/dev/null || true; set +a

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)" 2>/dev/null || SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"   # reclaim-tee
OUT_BUNDLE="${TOKENHIVE_OUT_BUNDLE:-${SCRIPT_DIR}/../bin/tokenhive-app-bundle.tar}"
GO_TOOLCHAIN="${SNP_TEE_GO_TOOLCHAIN:-}"

build_app() {
    local dst="$1"
    mkdir -p "$(dirname "${dst}")"
    echo "[pack] compiling snprunner -> ${dst}"
    ( cd "${REPO_ROOT}" && \
        GOTOOLCHAIN="${GO_TOOLCHAIN}" GOFLAGS=-mod=readonly GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
        go build -trimpath -tags 'enclave osusergo netgo static_build' \
        -ldflags "-s -w -buildid= -extldflags=-static" -o "${dst}" ./tokenhive/cloudtest/snp/runner )
    chmod 0755 "${dst}"
}

build() {
    local stage; stage="$(mktemp -d)"
    trap 'rm -rf "${stage}"' EXIT
    build_app "${stage}/app"
    chmod 0755 "${stage}/app"
    # Deterministic tar regardless of the host's tar flavor (macOS bsdtar has no
    # --sort; GNU tar lives in the image builder), so the bundle digest is
    # byte-reproducible: sorted names, fixed owner/group, fixed mtime.
    python3 - "${OUT_BUNDLE}" "${stage}" <<'PY'
import os, sys, tarfile
out, src = sys.argv[1], sys.argv[2]
tar = tarfile.open(out, "w", format=tarfile.GNU_FORMAT)
for name in sorted(os.listdir(src)):
    p = os.path.join(src, name)
    arc = "./" + name
    ti = tar.gettarinfo(p, arcname=arc)
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    ti.mtime = 1735689600
    if os.path.isdir(name):
        ti.mode = 0o755
    else:
        ti.mode = 0o755 if os.access(p, os.X_OK) else 0o644
    with open(p, "rb") as fh:
        tar.addfile(ti, fh)
tar.close()
PY
    rm -rf "${stage}"; trap - EXIT
    digest
}

digest() {
    local tar="${1:-${OUT_BUNDLE}}"
    [[ -f "${tar}" ]] || { echo "no bundle ${tar}; run ./pack.sh build" >&2; exit 1; }
    echo "snp-app:$(sha256sum "${tar}" | cut -d' ' -f1)"
}

case "${1:-build}" in
    build) build ;;
    digest) digest "${2:-}" ;;
    clean)
        rm -f "${OUT_BUNDLE}"
        echo "[pack] removed ${OUT_BUNDLE}"
        ;;
    *) echo "usage: $0 {build [OUT]|digest [TAR]|clean}" >&2; exit 1 ;;
esac
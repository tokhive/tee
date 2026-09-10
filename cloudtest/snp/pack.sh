#!/bin/bash
set -euo pipefail
# Build the TokenHive SNP app bundle — the measured `./app` an SNP loader boots
# (see ../../deploy/snp-build.sh). Here `./app` is the REAL tokenhive tee binary
# (compiled with -tags sevsnp); the loader runs two copies of it — a privileged
# attestation broker and an unprivileged resident TEE server. The bundle tar's
# sha256 IS SNP_APP_HASH: the loader hashes these exact bytes into PCR 8 and
# re-exports the hash to the app process as SNP_APP_HASH. Determinism therefore
# matters — the same inputs must yield the same digest cross-host, or a verifier
# pins a value we can't rebuild.
#
#   ./pack.sh build [OUT]   build tokenhive-app-bundle.tar
#   ./pack.sh digest [TAR]  print the snp-app: digest log line for a bundle
#   ./pack.sh clean         remove build artifacts
#
# Modes (env flags, checked in this order):
#   TOKENHIVE_BUILD_STUB=1   heartbeat-only ./app for boot diagnostics
#   TOKENHIVE_BUILD_SINGLE=1 supervisor ./app that runs the whole loop (tee+hub+
#                            agent+mockprovider) inside one confidential instance
#   default                  real tee as ./app + bundled hub-ca (cross-host mode)
# OUT defaults to ../bin/tokenhive-app-bundle.tar. Set SNP_HUB_CA to a PEM that
# signs the Hub client certificate; it is staged inside the bundle as
# ./mtls/hub-ca.pem so the TEE accepts only that Hub CA. Runtime config (relay
# URL, ports, bootstrap token) is injected per-launch via EC2 user-data, so the
# measured bundle never needs a rebuild just to change routing.
set -a; source ../.env 2>/dev/null || true; set +a

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)" 2>/dev/null || SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"   # reclaim-tee
OUT_BUNDLE="${TOKENHIVE_OUT_BUNDLE:-${SCRIPT_DIR}/../bin/tokenhive-app-bundle.tar}"
GO_TOOLCHAIN="${SNP_TEE_GO_TOOLCHAIN:-}"

# gobuild <pkg> <dst> [tags]: static linux/amd64 build shared by the real tee,
# the diagnostic stub, and the supervisor-bundle services (hub/agent/mockprovider
# have no sevsnp-specific code, only the tee passes tags).
gobuild() {
    local pkg="$1" dst="$2" tags="${3:-}"
    mkdir -p "$(dirname "${dst}")"
    ( cd "${REPO_ROOT}" && \
        GOTOOLCHAIN="${GO_TOOLCHAIN}" GOFLAGS=-mod=readonly GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
        go build -trimpath ${tags:+-tags "$tags"} \
        -ldflags "-s -w -buildid= -extldflags=-static" -o "${dst}" "${pkg}" )
    chmod 0755 "${dst}"
}

# bundle_ca stages the Hub mTLS CA inside the bundle so the unprivileged TEE app
# can demand a Hub client certificate signed by it at /run/bundle/mtls/hub-ca.pem.
bundle_ca() {
    local stage="$1"
    if [[ -n "${SNP_HUB_CA:-}" && -f "${SNP_HUB_CA}" ]]; then
        mkdir -p "${stage}/mtls"
        cp "${SNP_HUB_CA}" "${stage}/mtls/hub-ca.pem"
        chmod 0644 "${stage}/mtls/hub-ca.pem"
        echo "[pack] bundled Hub mTLS CA -> ./mtls/hub-ca.pem (${SNP_HUB_CA})"
    else
        echo "[pack] warning: no SNP_HUB_CA; mTLS client verification will use missing CA"
    fi
}

# bundle_mp stages the mock AI provider's TLS identity inside the bundle: the
# CA is what the TEE trusts for the upstream leg (TEE_CA, no-sshd host), and
# the cert/key let the in-bundle mock provider serve that same identity in
# single-instance mode. The cross-host deploy sends the same files to the
# ordinary host's mock provider.
bundle_mp() {
    local stage="$1"
    if [[ -n "${SNP_MP_CA:-}" && -f "${SNP_MP_CA}" ]]; then
        mkdir -p "${stage}/mtls"
        cp "${SNP_MP_CA}" "${stage}/mtls/mp-ca.pem"
        chmod 0644 "${stage}/mtls/mp-ca.pem"
        echo "[pack] bundled mock-provider CA -> ./mtls/mp-ca.pem (${SNP_MP_CA})"
    else
        echo "[pack] warning: no SNP_MP_CA; TEE upstream TLS will use system roots"
    fi
    if [[ -n "${SNP_MP_CERT:-}" && -f "${SNP_MP_CERT}" && -n "${SNP_MP_KEY:-}" && -f "${SNP_MP_KEY}" ]]; then
        cp "${SNP_MP_CERT}" "${stage}/mtls/mp-cert.pem"
        cp "${SNP_MP_KEY}"  "${stage}/mtls/mp-key.pem"
        chmod 0644 "${stage}/mtls/mp-cert.pem" "${stage}/mtls/mp-key.pem"
        echo "[pack] bundled mock-provider identity -> ./mtls/mp-cert.pem + mp-key.pem"
    else
        echo "[pack] warning: SNP_MP_CERT/KEY missing; mock provider TLS will use a runtime-generated CA"
    fi
}

# build_single packs a one-instance topology bundle: ./app is the supervisor
# (tokenhive/cmd/single) and the real services travel alongside it as ./svc/*,
# plus the Hub mTLS identity ./mtls/{hub-ca,hub-cert,hub-key}.pem. With
# TOKENHIVE_SUPERVISE=1 in user-data the supervisor runs mockprovider+tee+hub+
# agent all on loopback inside the single confidential instance; without it the
# supervisor just execs ./svc/tee (identical behavior to the cross-host bundle).
# Requires SNP_HUB_CA / SNP_HUB_CERT / SNP_HUB_KEY (the gencerts outputs).
build_single() {
    local stage="$1"
    echo "[pack] compiling supervisor ./app + svc/*"
    gobuild ./tokenhive/cmd/single        "${stage}/app"
    gobuild ./tokenhive/cmd/tee "${stage}/svc/tee" 'sevsnp enclave osusergo netgo static_build'
    gobuild ./tokenhive/cmd/hub          "${stage}/svc/hub"
    gobuild ./tokenhive/cmd/agent        "${stage}/svc/agent"
    gobuild ./tokenhive/cmd/mockprovider "${stage}/svc/mockprovider"
    bundle_ca "${stage}"
    bundle_mp "${stage}"
    if [[ -n "${SNP_HUB_CERT:-}" && -f "${SNP_HUB_CERT}" && -n "${SNP_HUB_KEY:-}" && -f "${SNP_HUB_KEY}" ]]; then
        cp "${SNP_HUB_CERT}" "${stage}/mtls/hub-cert.pem"
        cp "${SNP_HUB_KEY}"  "${stage}/mtls/hub-key.pem"
        chmod 0644 "${stage}/mtls/hub-cert.pem" "${stage}/mtls/hub-key.pem"
        echo "[pack] bundled Hub client identity -> ./mtls/hub-cert.pem + hub-key.pem"
    else
        echo "[pack] warning: SNP_HUB_CERT/KEY missing; single-mode Hub cannot do mTLS"
    fi
}

build() {
    local stage; stage="$(mktemp -d)"
    trap 'rm -rf "${stage}"' EXIT
    if [[ "${TOKENHIVE_BUILD_SINGLE:-0}" == "1" ]]; then
        build_single "${stage}"
    elif [[ "${TOKENHIVE_BUILD_STUB:-0}" == "1" ]]; then
        gobuild ./tokenhive/cloudtest/snp/stub "${stage}/app"
    else
        echo "[pack] compiling tokenhive/cmd/tee (sevsnp) -> app"
        gobuild ./tokenhive/cmd/tee "${stage}/app" 'sevsnp enclave osusergo netgo static_build'
        bundle_ca "${stage}"
        bundle_mp "${stage}"
    fi
    # Deterministic tar regardless of the host's tar flavor (macOS bsdtar has no
    # --sort; GNU tar lives in the image builder), so the bundle digest is
    # byte-reproducible: fixed owner/group, fixed mtime, normalized modes.
    # os.walk + tar.add(recursive=False) keeps it concise while still emitting
    # nested paths (e.g. ./mtls/hub-ca.pem) byte-identical across rebuilds.
    python3 - "${OUT_BUNDLE}" "${stage}" <<'PY'
import os, sys, tarfile
out, src = sys.argv[1], sys.argv[2]

def norm(ti):
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    ti.mtime = 1735689600
    ti.mode = 0o755 if ti.isdir() or (ti.mode & 0o111) else 0o644
    return ti

with tarfile.open(out, "w", format=tarfile.GNU_FORMAT) as tar:
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames.sort()
        filenames.sort()
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            tar.add(p, arcname="./" + os.path.relpath(p, src), recursive=False, filter=norm)
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
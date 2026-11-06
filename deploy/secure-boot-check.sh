#!/bin/bash
# Every Secure Boot artifact below has to describe ONE key. R signs the UKI and
# its certificate is what db trusts, so the image boots only when those agree;
# the verifier rejects the firmware event log unless it holds the same public
# half, so the image is accepted only when that copy agrees too.
#
#   R.key       signs the UKI                      (private, gitignored, offline ok)
#   R.crt.pem   the certificate db carries         (source of R.esl)
#   R.crt.der   the same certificate for GCP's signature-database
#   R.pub.pem   the verification anchor on the image side
#   shared/secure_boot_release_pub.pem   this repository's build-time default
#
# Half a rotation is invisible at build time and fatal at run time: the TEE
# comes up and the verifier refuses it with "event log does not prove an R-only
# post-separator Secure Boot policy". snp-build.sh runs this on the build host;
# --release-pem <path> checks a verifier's own key file instead of the shared
# copy, which is what a production Hub holds (its key is not this repository's).
set -euo pipefail
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SECURE_BOOT_DIR="${REPO_ROOT}/deploy/secure-boot"
RELEASE_PUB="${REPO_ROOT}/shared/secure_boot_release_pub.pem"

# Messages name paths the way the operator wrote them: deploy/secure-boot/...,
# not an absolute path that has to be read down to its last segment.
rel() { printf '%s' "${1#"${REPO_ROOT}/"}"; }
fail() { echo "secure-boot: $*" >&2; exit 1; }

# The verifier on the deploy host may read its key from a file of its own rather
# than from this repository (a production R.pub.pem is not shared with
# developers). --release-pem checks that file instead of the copy under shared/,
# which is only this repository's build-time default.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --release-pem)
            [[ $# -ge 2 && -n "$2" ]] || fail "--release-pem needs a path"
            RELEASE_PUB="$2"
            shift 2 ;;
        *) fail "unknown argument $1 (usage: secure-boot-check.sh [--release-pem <path>])" ;;
    esac
done

command -v openssl >/dev/null 2>&1 || fail "openssl is required to compare the release keys"

# spki_sha256 <artifact> <kind>: sha256 of the DER SubjectPublicKeyInfo. That
# encoding is the point: a private key, a certificate and a bare public key are
# different bytes for the same key, so comparing files would prove nothing.
# -passin pass: turns an encrypted key into an immediate failure instead of a
# prompt that waits for a build host nobody is watching.
spki_sha256() {
    {
        case "$2" in
            key)  openssl pkey -in "$1" -passin pass: -pubout -outform DER ;;
            pub)  openssl pkey -pubin -in "$1" -outform DER ;;
            cert) openssl x509 -in "$1" -noout -pubkey | openssl pkey -pubin -outform DER ;;
            der)  openssl x509 -in "$1" -inform DER -noout -pubkey | openssl pkey -pubin -outform DER ;;
            *)    return 1 ;;
        esac
    } 2>/dev/null | openssl dgst -sha256 | sed -e 's/^.*=[[:space:]]*//' || true
}

want="" first=""
for spec in "${SECURE_BOOT_DIR}/R.pub.pem:pub" \
            "${SECURE_BOOT_DIR}/R.crt.pem:cert" \
            "${SECURE_BOOT_DIR}/R.crt.der:der" \
            "${RELEASE_PUB}:pub"; do
    path="${spec%:*}" kind="${spec##*:}"
    [[ -f "${path}" ]] || fail "missing $(rel "${path}")"
    fp="$(spki_sha256 "${path}" "${kind}")"
    [[ -n "${fp}" ]] || fail "no public key in $(rel "${path}")"
    if [[ -z "${want}" ]]; then
        want="${fp}" first="${path}"
    elif [[ "${fp}" != "${want}" ]]; then
        fail "$(printf '%s is %s but %s is %s\nsecure-boot: these must be one key: rotate them together, commit the public half, and rebuild the Hub' \
            "$(rel "${path}")" "${fp}" "$(rel "${first}")" "${want}")"
    fi
done

# R.key may sit in an offline vault rather than on the build host, so it is
# checked only when it is here. When it is, it has to be the key its own
# certificate names: signing with a key db does not trust bricks the boot.
if [[ -f "${SECURE_BOOT_DIR}/R.key" ]]; then
    key_fp="$(spki_sha256 "${SECURE_BOOT_DIR}/R.key" key)"
    [[ "${key_fp}" == "${want}" ]] || fail "$(printf '%s is %s but its certificate names %s; re-issue R.crt.pem/R.crt.der/R.esl/aws-uefi-data.b64 from this key' \
        "deploy/secure-boot/R.key" "${key_fp:-<unreadable>}" "${want}")"
fi

# The image boots only if db trusts the certificate this build signs with, and
# db is the one artifact whose hash proves nothing: R.esl is a signature list
# with a header, so its bytes differ from R.crt.der while carrying them verbatim.
# Containment is the check, and it catches the rotation that re-issued
# R.crt.pem/R.crt.der but forgot cert-to-efi-sig-list -- which otherwise only
# shows up as an instance that will not boot.
#
# aws-uefi-data.b64 is deliberately not checked here: it is AWS's own container
# (opaque without uefivars), so the manual `uefivars -i aws -o json` in §2 stays
# the way to confirm db. The ESL is its input, so the gap is one step wide.
if [[ -f "${SECURE_BOOT_DIR}/R.esl" ]]; then
    PY="${PYTHON:-python3}"
    command -v "${PY}" >/dev/null 2>&1 || fail "${PY} is required to read R.esl"
    "${PY}" - "${SECURE_BOOT_DIR}/R.crt.der" "${SECURE_BOOT_DIR}/R.esl" <<'PY' || exit 1
import sys

der_path, esl_path = sys.argv[1:3]
if open(der_path, "rb").read() not in open(esl_path, "rb").read():
    sys.exit("secure-boot: deploy/secure-boot/R.esl does not contain the certificate from R.crt.der\n"
             "secure-boot: re-run cert-to-efi-sig-list for the current R.crt.pem, then rebuild\n"
             "secure-boot: aws-uefi-data.b64 with uefivars")
PY
fi

echo "secure-boot: one key, SPKI sha256 ${want}"


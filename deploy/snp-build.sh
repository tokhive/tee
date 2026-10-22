#!/bin/bash
set -euo pipefail

# Build a SEV-SNP TEE image for one role x cloud and package it as a GCP image
# or AWS AMI, ready for snp-pair.sh. One script for the whole pipeline:
# compile (loader + tee binary) -> two-tier image in Docker (snp-image/tier-
# build.sh) -> snp-tier.raw -> cloud image. The app-bundle sha256 IS the
# cross-cloud snp-app: digest (printed at the end).
#
#   ./deploy/snp-build.sh <k|t> <gcp|aws> [TAG]   default TAG = tee<role>-<cloud>
#   ./deploy/snp-build.sh clean
#
# Run with the proxy SET (the AWS steps need it); go/docker/gcloud/gsutil steps
# unset it themselves. Deployment-specific values come from deploy/.env.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then set -a; source "${SCRIPT_DIR}/.env"; set +a; fi
source "${SCRIPT_DIR}/_lib.sh"
set -a; source "${SCRIPT_DIR}/snp-image/pins.env"; set +a
source "${SCRIPT_DIR}/snp-image/app-pins.sh"
source "${SCRIPT_DIR}/snp-image/source-commit.sh"

: "${SNP_LOADER_GO_TOOLCHAIN:?set SNP_LOADER_GO_TOOLCHAIN in snp-image/pins.env}"
: "${SNP_TEE_GO_TOOLCHAIN:?set SNP_TEE_GO_TOOLCHAIN in snp-image/pins.env}"
: "${SNP_APT_SNAPSHOT:?set SNP_APT_SNAPSHOT in snp-image/pins.env}"

# SNP_CA_IMAGE is an app-bundle input as well as the TLS bootstrap image for
# the base builder. Preserve the current value for the base; historical app
# reconstruction replaces only the app copy below.
SNP_BASE_CA_IMAGE="${SNP_CA_IMAGE:?set SNP_CA_IMAGE in snp-image/pins.env}"

GCP_PROJECT="${GCP_PROJECT:?set GCP_PROJECT in deploy/.env}"
IMG_DIR="${SCRIPT_DIR}/snp-image"
SECURE_BOOT_DIR="${SCRIPT_DIR}/secure-boot"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RAW="${IMG_DIR}/snp-tier.raw"
BUNDLE_HOST="${IMG_DIR}/app-bundle.tar"
DOCKER="${DOCKER:-docker}"
AWS_TYPE="${AWS_SNP_TYPE:-c6a.large}"

for required in PK.crt.der KEK.crt.der R.crt.der R.crt.pem R.pub.pem R.key aws-uefi-data.b64; do
    [[ -f "${SECURE_BOOT_DIR}/${required}" ]] || {
        echo "[build] missing Secure Boot artifact ${SECURE_BOOT_DIR}/${required}" >&2
        exit 1
    }
done

# The AWS steps go through a flaky local proxy; let the CLI retry dropped
# connections itself so one blip doesn't kill a 10-min VM-import build.
export AWS_MAX_ATTEMPTS="${AWS_MAX_ATTEMPTS:-10}" AWS_RETRY_MODE="${AWS_RETRY_MODE:-standard}"

# Per-cloud kernel + modules; versions pinned in snp-image/pins.env.
kernel_for() { [[ "$1" == aws ]] && echo "${SNP_AWS_KERNEL_PKG}" || echo "${SNP_GCP_KERNEL_PKG}"; }
modules_for() { [[ "$1" == aws ]] && echo "ena tsm_report sev-guest" || echo "gve"; }

_np() { unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY ftp_proxy FTP_PROXY 2>/dev/null || true; }
g() { ( _np; gcloud_retry gcloud "$@" --project="${GCP_PROJECT}" ); }

build_loader() {
    local dst="${IMG_DIR}/mkosi.extra/usr/local/bin/snp-loader"
    echo "[build] compiling Secure Boot loader..."
    mkdir -p "$(dirname "${dst}")"
    # -buildvcs=false keeps the loader independent of the app commit. The UKI is
    # authorized by R; its PCR 11 value is diagnostic rather than allowlisted.
    ( _np; cd "${IMG_DIR}/loader" && GOTOOLCHAIN="${SNP_LOADER_GO_TOOLCHAIN}" GOFLAGS=-mod=readonly GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
        go build -trimpath -buildvcs=false -ldflags "-buildid=" -o "${dst}" . )
    chmod 0755 "${dst}"
    echo "[build] loader sha256: $(sha256sum "${dst}" | cut -d' ' -f1)"
}

# build_bundle compiles tee_<role> + stages mpcl circuits + CA certs into the
# deterministic app bundle (its sha256 is the cross-cloud snp-app: digest);
# or, when SNP_EXTERNAL_BUNDLE is set, adopts an already-built app bundle
# verbatim (used by tokenhive/cloudtest/snp/pack.sh whose app is its own loader
# probe, not a tee_k/tee_t binary).
build_bundle() {
    local role="$1"
    if [[ -n "${SNP_EXTERNAL_BUNDLE:-}" ]]; then
        cp "${SNP_EXTERNAL_BUNDLE}" "${BUNDLE_HOST}"
        echo "[build] adopting external app bundle -- external-bundle=${SNP_EXTERNAL_BUNDLE}"
        echo "[build] app bundle: $(du -h "${BUNDLE_HOST}" | cut -f1)  sha256: $(sha256sum "${BUNDLE_HOST}" | cut -d' ' -f1)"
        return
    fi
    local dst="${IMG_DIR}/mkosi.extra/usr/local/bin/snp-tee${role}"
    echo "[build] compiling tee_${role}..."
    mkdir -p "$(dirname "${dst}")"
    ( _np; cd "${REPO_ROOT}" && GOTOOLCHAIN="${SNP_TEE_GO_TOOLCHAIN}" GOFLAGS=-mod=readonly GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
        go build -trimpath -tags 'enclave osusergo netgo static_build' \
        -ldflags "-s -w -buildid= -extldflags=-static" -o "${dst}" "./tee_${role}" )
    chmod 0755 "${dst}"
    local stage; stage="$(mktemp -d)"
    cp "${dst}" "${stage}/app"
    local mpcdir; mpcdir="$( _np; cd "${REPO_ROOT}" && GOTOOLCHAIN="${SNP_TEE_GO_TOOLCHAIN}" GOFLAGS=-mod=readonly go list -m -f '{{.Dir}}' github.com/markkurossi/mpc )"
    mkdir -p "${stage}/mpcl"; cp -r "${mpcdir}/pkg" "${stage}/mpcl/pkg"
    mkdir -p "${stage}/etc/ssl/certs"
    ${DOCKER} run --rm "${SNP_CA_IMAGE}" cat /etc/ssl/certs/ca-certificates.crt > "${stage}/etc/ssl/certs/ca-certificates.crt"
    # mpcl is copied from Go's read-only module cache (0444/0555), whose perms
    # vary by host and block the rm below. Canonicalize modes so the tar (-> app
    # digest) is reproducible cross-host AND the staging dir is removable.
    find "${stage}" -type d -exec chmod 0755 {} +
    find "${stage}" -type f -exec chmod 0644 {} +
    chmod 0755 "${stage}/app"
    tar --sort=name --format=gnu --mtime="@1735689600" --owner=0 --group=0 --numeric-owner -C "${stage}" -cf "${BUNDLE_HOST}" .
    rm -rf "${stage}"
    echo "[build] app bundle: $(du -h "${BUNDLE_HOST}" | cut -f1)  sha256: $(sha256sum "${BUNDLE_HOST}" | cut -d' ' -f1)"
}

build_raw() {
    local cloud="$1"
    local img="snp-img-builder-${cloud}"
    echo "[build] two-tier image in Docker (cloud=${cloud} kernel=$(kernel_for "$cloud"))..."
    # Identity-only (verify) builds skip systemd-repart -> no --privileged, no /dev.
    local priv="--privileged -v /dev:/dev" idonly=""
    [[ "${SNP_BUILD_ONLY:-0}" == 1 ]] && { priv=""; idonly="-e SNP_IDENTITY_ONLY=1"; }
    ( _np; ${DOCKER} build --platform=linux/amd64 --build-arg KERNEL_PKG="$(kernel_for "$cloud")" \
        --build-arg CA_IMAGE="${SNP_BASE_CA_IMAGE}" --build-arg APT_SNAPSHOT="${SNP_APT_SNAPSHOT}" \
        --build-arg APT_MIRROR="${SNP_APT_MIRROR:-snapshot}" \
        --build-arg UBUNTU_DIGEST="${SNP_UBUNTU_DIGEST}" \
        --build-arg SYSTEMD_BOOT_VER="${SNP_SYSTEMD_BOOT_VER}" --build-arg SYSTEMD_UKIFY_VER="${SNP_SYSTEMD_UKIFY_VER}" \
        --build-arg SYSTEMD_VER="${SNP_SYSTEMD_VER}" --build-arg ZSTD_VER="${SNP_ZSTD_VER}" \
        --build-arg CPIO_VER="${SNP_CPIO_VER}" --build-arg BINUTILS_VER="${SNP_BINUTILS_VER}" \
        --build-arg http_proxy= --build-arg https_proxy= --build-arg HTTP_PROXY= --build-arg HTTPS_PROXY= --build-arg no_proxy= \
        -t "${img}" "${IMG_DIR}"
      ${DOCKER} run --rm --platform=linux/amd64 ${priv} \
        -e http_proxy= -e https_proxy= -e HTTP_PROXY= -e HTTPS_PROXY= \
        -e APP_BIN=/work/app-bundle.tar -e MODULES="$(modules_for "$cloud")" -e SNP_CMDLINE="${SNP_CMDLINE:-}" \
        -e SNP_SECUREBOOT_KEY=/secure-boot/R.key -e SNP_SECUREBOOT_CERT=/secure-boot/R.crt.pem \
        -e SNP_PCR_BANK="$([[ "${cloud}" == aws ]] && echo sha384 || echo sha256)" ${idonly} \
        -v "${IMG_DIR}:/work" -v "${SECURE_BOOT_DIR}:/secure-boot:ro" "${img}" bash /work/tier-build.sh )
}

package_gcp() {
    local tag="$1"
    local image="snp-${tag}" bucket="gs://${GCP_PROJECT}-snp-images"
    local tmp; tmp="$(mktemp -d)"
    cp --reflink=auto "${RAW}" "${tmp}/disk.raw"
    tar --format=oldgnu -C "${tmp}" -Sczf "${tmp}/${image}.tar.gz" disk.raw
    g storage buckets create "${bucket}" --location=US >/dev/null 2>&1 || true
    echo "[image] uploading ${image}.tar.gz..."
    ( _np; gsutil -q cp "${tmp}/${image}.tar.gz" "${bucket}/${image}.tar.gz" )
    g compute images delete "${image}" --quiet >/dev/null 2>&1 || true
    g compute images create "${image}" --source-uri="${bucket}/${image}.tar.gz" \
        --platform-key-file="${SECURE_BOOT_DIR}/PK.crt.der" \
        --key-exchange-key-file="${SECURE_BOOT_DIR}/KEK.crt.der" \
        --signature-database-file="${SECURE_BOOT_DIR}/R.crt.der" \
        --guest-os-features=UEFI_COMPATIBLE,SEV_SNP_CAPABLE,VIRTIO_SCSI_MULTIQUEUE
    rm -rf "${tmp}"
    echo "[image] GCP image ${image} created -> snp-pair.sh SNP_K_IMAGE/SNP_T_IMAGE=${image}"
}

package_aws() {
    local tag="$1"
    local image="snp-${tag}" region="${AWS_SNP_REGION:?set AWS_SNP_REGION in deploy/.env}"
    local acct bucket key tmp vmdk
    acct="$(aws sts get-caller-identity --query Account --output text)"
    # The staging object is named after the app the disk carries, not after the
    # image alone. Under a fixed name a stale object is indistinguishable from
    # this build's, and that is not hypothetical: when an upload did not land,
    # import-snapshot silently consumed the previous build's disk and the AMI was
    # registered tagged with this build's digest -- the digest the launcher pins
    # the TEE to, and the one the Hub is then told to expect.
    bucket="${SNP_S3_BUCKET:-snp-vmimport-${acct}}"; key="${image}-${DIGEST#snp-app:}.vmdk"
    tmp="$(mktemp -d)"; vmdk="${tmp}/disk.vmdk"
    echo "[image] raw -> deterministic streamOptimized VMDK..."
    qemu-img convert -f raw -O vmdk -o subformat=streamOptimized "${RAW}" "${vmdk}"
    # qemu writes CID with %x, so a value under 0x10000000 is short and an
    # unanchored 8-hex-digit match lands on parentCID instead -> AWS rejects it
    # as a parentless delta disk. Anchor both fields to the descriptor region.
    python3 - "${vmdk}" <<'PY'
import re,struct,sys
p=sys.argv[1]; b=bytearray(open(p,'rb').read())
if bytes(b[:4])!=b'KDMV': raise SystemExit('[image] not a VMDK sparse extent')
off=struct.unpack_from('<Q',b,28)[0]*512; size=struct.unpack_from('<Q',b,36)[0]*512
desc=bytes(b[off:off+size]).rstrip(b'\x00')
desc,n1=re.subn(rb'(?m)^CID=[0-9a-fA-F]+$',b'CID=00000001',desc)
desc,n2=re.subn(rb'(?m)^parentCID=[0-9a-fA-F]+$',b'parentCID=ffffffff',desc)
if n1!=1 or n2!=1: raise SystemExit(f'[image] CID patch failed (CID={n1} parentCID={n2})')
if len(desc)>size: raise SystemExit('[image] descriptor overflow')
b[off:off+size]=desc+b'\x00'*(size-len(desc))
open(p,'wb').write(b)
PY
    echo "[image] uploading s3://${bucket}/${key}..."
    # Idempotently ensure the VM-import staging bucket. cp does not create it.
    # Creating an already-owned bucket is a benign BucketAlreadyOwnedByYou, so we
    # retry on that; any other failure (e.g. missing s3:CreateBucket) surfaces
    # loudly here instead of becoming a confusing NoSuchBucket on cp below.
    if ! aws s3 mb "s3://${bucket}" --region "${region}" 2>/tmp/snp-mb.err; then
        grep -q "BucketAlreadyOwnedByYou" /tmp/snp-mb.err \
            || { echo "[image] cannot ensure bucket s3://${bucket}:" >&2; cat /tmp/snp-mb.err >&2; rm -f /tmp/snp-mb.err; exit 1; }
    fi
    rm -f /tmp/snp-mb.err
    # A single PUT rather than `s3 cp`: cp switches to a multipart upload above
    # 8 MB, and S3 then reports a composite checksum (sha256 of the part
    # checksums, suffixed "-N") which can never equal the file's own digest.
    # The VMDK is ~31 MB, far below the 5 GB single-PUT limit.
    aws --region "${region}" s3api put-object \
        --bucket "${bucket}" --key "${key}" --body "${vmdk}" --checksum-algorithm SHA256 >/dev/null
    # Fail closed. import-snapshot reads whatever sits at this key, so prove the
    # object is the bytes we just wrote before paying for an import and before
    # registering an AMI that claims a digest. This is the check whose absence
    # turned a silent no-op upload into a mislabelled image.
    local want got
    want="$(python3 -c 'import base64,hashlib,sys; print(base64.b64encode(hashlib.sha256(open(sys.argv[1],"rb").read()).digest()).decode())' "${vmdk}")"
    rm -rf "${tmp}"
    got="$(aws --region "${region}" s3api head-object --bucket "${bucket}" --key "${key}" --checksum-mode ENABLED --query ChecksumSHA256 --output text 2>/dev/null || true)"
    [[ -n "${got}" && "${got}" == "${want}" ]] || {
        echo "[image] upload verification failed for s3://${bucket}/${key}" >&2
        echo "[image]   object checksum = ${got:-<unreadable>}" >&2
        echo "[image]   local  checksum = ${want}" >&2
        echo "[image] refusing to import: the image would not measure the digest it is tagged with" >&2
        exit 1
    }
    local task; task="$(aws --region "${region}" ec2 import-snapshot --description "${image}" \
        --disk-container "Format=VMDK,UserBucket={S3Bucket=${bucket},S3Key=${key}}" --query 'ImportTaskId' --output text)"
    echo "[image] import-snapshot ${task}; waiting (5-15 min)..."
    local snap="" status
    for i in $(seq 1 90); do
        status="$(aws --region "${region}" ec2 describe-import-snapshot-tasks --import-task-ids "${task}" --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.Status' --output text 2>/dev/null || true)"
        echo "  [${i}] status=${status}"
        case "${status}" in
            completed) snap="$(aws --region "${region}" ec2 describe-import-snapshot-tasks --import-task-ids "${task}" --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.SnapshotId' --output text)"; break ;;
            deleted|deleting) echo "[image] import failed" >&2; exit 1 ;;
        esac
        sleep 20
    done
    [[ -n "${snap}" && "${snap}" != None ]] || { echo "[image] no snapshot produced" >&2; exit 1; }
    # The snapshot is a copy of the object, so the staging object is spent. Drop
    # it: the name is content-addressed, so leaving it would only cost 30 MB per
    # build forever.
    aws --region "${region}" s3 rm "s3://${bucket}/${key}" >/dev/null 2>&1 \
        || echo "[image] warning: staging object s3://${bucket}/${key} was not removed" >&2
    # Deregister the previous AMI and release its EBS snapshots
    aws --region "${region}" ec2 deregister-image \
        --image-id "$(aws --region "${region}" ec2 describe-images --owners self --filters "Name=name,Values=${image}" --query 'Images[-1].ImageId' --output text 2>/dev/null)" \
        --delete-associated-snapshots >/dev/null 2>&1 || true
    local uefi_data; uefi_data="$(tr -d '\n' < "${SECURE_BOOT_DIR}/aws-uefi-data.b64")"
    # Tag the image with the app bundle digest it embeds. The bundle rides
    # inside this AMI, so the digest is a statement about the image, and it has
    # to travel with the image: a launcher that re-hashed its local bin/ instead
    # would record whatever the last build left there, which is not necessarily
    # what this image measures (a build that packed but failed before registering
    # leaves exactly that). `crosshost.sh up` reads this tag to pin the TEE.
    local ami; ami="$(aws --region "${region}" ec2 register-image --name "${image}" \
        --architecture x86_64 --virtualization-type hvm --boot-mode uefi --ena-support --sriov-net-support simple \
        --tpm-support v2.0 --root-device-name /dev/xvda \
        --uefi-data="${uefi_data}" \
        --block-device-mappings "DeviceName=/dev/xvda,Ebs={SnapshotId=${snap},DeleteOnTermination=true,VolumeType=gp3}" \
        --tag-specifications "ResourceType=image,Tags=[{Key=snp-app,Value=${DIGEST#snp-app:}}]" \
        --query 'ImageId' --output text)"
    echo "[image] AMI ${ami} (${image}) registered -> snp-pair.sh SNP_T_IMAGE/SNP_K_IMAGE tag = ${tag}"
}

if [[ "${1:-}" == clean ]]; then
    rm -rf "${IMG_DIR}"/*.raw "${BUNDLE_HOST}" "${IMG_DIR}/mkosi.extra/usr/local/bin" 2>/dev/null \
        || sudo rm -rf "${IMG_DIR}"/*.raw "${BUNDLE_HOST}" "${IMG_DIR}/mkosi.extra/usr/local/bin"
    echo "[clean] done"; exit 0
fi

# Persist the just-built digest to deploy/snp-digests.env (per-role, keyed on
# COMMIT) so update-image-history.sh / snp-redeploy-fleet.sh read it, no hand-edit.
record_digest_env() {
    local role="$1" digest="$2" f="${SCRIPT_DIR}/snp-digests.env"
    local commit kd="" td=""
    commit="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
    if [[ -f "${f}" ]] && grep -qx "COMMIT=${commit}" "${f}"; then
        kd="$(sed -n 's/^SNP_K_DIGEST=//p' "${f}")"
        td="$(sed -n 's/^SNP_T_DIGEST=//p' "${f}")"
    fi
    [[ "${role}" == k ]] && kd="${digest}" || td="${digest}"
    { echo "SNP_K_DIGEST=${kd}"; echo "SNP_T_DIGEST=${td}"; echo "COMMIT=${commit}"; } > "${f}"
    echo "[build]   recorded ${ROLE_UC} digest in deploy/snp-digests.env (COMMIT=${commit:0:7})"
}

ROLE="${1:?usage: $0 <k|t> <gcp|aws> [TAG]}"
CLOUD="${2:?usage: $0 <k|t> <gcp|aws> [TAG]}"
case "${ROLE}" in k|t) ;; *) echo "role must be k|t" >&2; exit 1 ;; esac
case "${CLOUD}" in gcp|aws) ;; *) echo "cloud must be gcp|aws" >&2; exit 1 ;; esac
TAG="${3:-tee${ROLE}-${CLOUD}}"
# ${VAR^^} is bash-4 syntax, but this script is run from the operator's Mac,
# where /bin/bash is 3.2. Deriving the uppercase label with tr keeps the two
# report lines at the end of the build from aborting on "bad substitution" --
# which would fail the build after the image was already registered.
ROLE_UC="$(tr '[:lower:]' '[:upper:]' <<< "${ROLE}")"

# Reproducible per-commit app build. The app is VCS-stamped, so its digest is
# commit-specific AND a dirty tree taints it. Default to the latest app_images
# commit recorded in image-history.json (i.e. what's allowlisted), override with
# SNP_BUILD_COMMIT. Build the app from a clean clone at that commit (like
# verify.sh — clone NOT worktree so buildvcs stamps the commit), sidestepping the
# working tree entirely. The loader/base stay commit-independent.
BUILD_COMMIT="${SNP_BUILD_COMMIT:-}"
if [[ -z "${BUILD_COMMIT}" && -f "${SCRIPT_DIR}/image-history.json" ]]; then
    BUILD_COMMIT="$(python3 -c "import json; a=[x for x in json.load(open('${SCRIPT_DIR}/image-history.json')).get('app_images',[]) if x.get('role')=='${ROLE}']; print(a[-1]['sourceCommit'] if a else '')" 2>/dev/null || true)"
fi
if [[ -n "${BUILD_COMMIT}" ]]; then
    CLONE_DIR="$(mktemp -d)"; trap 'rm -rf "${CLONE_DIR}"' EXIT
    echo "[build] app source: clean clone @ ${BUILD_COMMIT:0:12} (dirty-tree-immune)"
    snp_checkout_source_commit "${REPO_ROOT}" "${BUILD_COMMIT}" "${CLONE_DIR}"
    REPO_ROOT="${CLONE_DIR}"
    # The app toolchain and CA bundle are part of the recorded app identity, so
    # take them from the same source commit. Loader/base inputs remain the
    # current values loaded before the clone.
    snp_load_app_pins "${REPO_ROOT}/deploy/snp-image/pins.env"
fi

# Check the selected app source, not only the deployment worktree. This rejects
# an old SEV2-only commit or a verifier pinned to a different R before the image
# is signed. Certificate reissuance remains safe because the SPKI file is stable.
# Skipped when the app is adopted verbatim from an external bundle (the cloudtest
# SNP probe): the app byte blob is already fixed, its source commit's R is moot,
# and only the base loader/UKI (signed below with this R) carries the boot chain.
if [[ -z "${SNP_EXTERNAL_BUNDLE:-}" ]]; then
  cmp -s "${SECURE_BOOT_DIR}/R.pub.pem" "${REPO_ROOT}/shared/secure_boot_release_pub.pem" || {
      echo "[build] selected app source does not contain the deployed Secure Boot R public key" >&2
      exit 1
  }
fi

# The app digest is VCS-stamped (tracks the commit), so a dirty tree yields a
# vcs.modified artifact, not the clean-commit value. Refuse unless overridden.
# (When BUILD_COMMIT cloned above, REPO_ROOT is the clean clone -> passes.)
if [[ -n "$(git -C "${REPO_ROOT}" status --porcelain 2>/dev/null)" && "${SNP_ALLOW_DIRTY:-0}" != 1 ]]; then
    echo "[build] working tree is dirty -> app digest would be a vcs.modified artifact." >&2
    echo "[build] commit/stash first, set SNP_BUILD_COMMIT=<hash>, or SNP_ALLOW_DIRTY=1." >&2
    exit 1
fi

echo "[build] === tee_${ROLE}@${CLOUD} (tag ${TAG}) ==="
echo "[build] app inputs: ${SNP_TEE_GO_TOOLCHAIN}, ${SNP_CA_IMAGE}"
build_loader
build_bundle "${ROLE}"
build_raw "${CLOUD}"

# The base UKI is R-signed and verified through Secure Boot. Its hash is printed
# for diagnostics only; it is no longer a production pin or rollout dependency.
BASE_UKI="$(sha256sum "${IMG_DIR}/snp-base.efi" | cut -d' ' -f1)"

# App bundle (PCR 8) tracks the commit -> compute + report; operator allowlists.
DIGEST="snp-app:$(sha256sum "${BUNDLE_HOST}" | cut -d' ' -f1)"
# Optional guard: assert the reproduced digest matches an expected/allowlisted one.
if [[ -n "${SNP_EXPECT_DIGEST:-}" && "${SNP_EXPECT_DIGEST}" != "${DIGEST}" ]]; then
    echo "[build] DIGEST MISMATCH: built ${DIGEST}, expected ${SNP_EXPECT_DIGEST}" >&2
    echo "[build] base/toolchain/commit differ from the allowlisted build; do NOT deploy." >&2
    exit 1
fi
# SNP_BUILD_ONLY: identity verify (verify.sh) — emit digests, skip cloud packaging.
if [[ "${SNP_BUILD_ONLY:-0}" != 1 ]]; then
    [[ "${CLOUD}" == gcp ]] && package_gcp "${TAG}" || package_aws "${TAG}"
    record_digest_env "${ROLE}" "${DIGEST}"
fi
echo "[build] DONE tee_${ROLE}@${CLOUD}"
echo "[build]   base UKI   = ${BASE_UKI}  (diagnostic only; trust root is Secure Boot R)"
echo "[build]   app digest = ${DIGEST}  (commit $(git -C "${REPO_ROOT}" rev-parse --short HEAD))"
echo "[build]   -> record in deploy/image-history.json + allowlist on the router; pass to snp-pair.sh via SNP_${ROLE_UC}_DIGEST"

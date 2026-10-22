#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/app-pins.sh"

TEST_DIR="$(mktemp -d)"
trap 'rm -rf "${TEST_DIR}"' EXIT

OLD_PINS="${TEST_DIR}/old.env"
NEW_PINS="${TEST_DIR}/new.env"
OLD_CA="alpine@sha256:$(printf 'a%.0s' {1..64})"
NEW_CA="alpine@sha256:$(printf 'b%.0s' {1..64})"
printf '%s\n' \
    'SNP_LOADER_GO_TOOLCHAIN="go-old-loader"' \
    'SNP_TEE_GO_TOOLCHAIN="go1.26.5"' \
    "SNP_CA_IMAGE=\"${OLD_CA}\"" \
    'SNP_BASE_UKI_GCP="old-base"' >"${OLD_PINS}"
printf '%s\n' \
    'SNP_LOADER_GO_TOOLCHAIN="go-new-loader"' \
    'SNP_TEE_GO_TOOLCHAIN="go1.26.6"' \
    "SNP_CA_IMAGE=\"${NEW_CA}\"" \
    'SNP_BASE_UKI_GCP="new-base"' >"${NEW_PINS}"

# These represent the current, separately loaded base inputs. Loading app pins
# from either source revision must not modify them.
SNP_LOADER_GO_TOOLCHAIN="go1.26.0"
SNP_BASE_UKI_GCP="current-base"
SNP_BASE_CA_IMAGE="alpine@sha256:current-base-ca"

snp_load_app_pins "${OLD_PINS}"
[[ "${SNP_TEE_GO_TOOLCHAIN}" == go1.26.5 ]]
[[ "${SNP_CA_IMAGE}" == "${OLD_CA}" ]]
[[ "${SNP_LOADER_GO_TOOLCHAIN}" == go1.26.0 ]]
[[ "${SNP_BASE_UKI_GCP}" == current-base ]]
[[ "${SNP_BASE_CA_IMAGE}" == alpine@sha256:current-base-ca ]]

snp_load_app_pins "${NEW_PINS}"
[[ "${SNP_TEE_GO_TOOLCHAIN}" == go1.26.6 ]]
[[ "${SNP_CA_IMAGE}" == "${NEW_CA}" ]]
[[ "${SNP_LOADER_GO_TOOLCHAIN}" == go1.26.0 ]]
[[ "${SNP_BASE_UKI_GCP}" == current-base ]]
[[ "${SNP_BASE_CA_IMAGE}" == alpine@sha256:current-base-ca ]]

LEGACY_PINS="${TEST_DIR}/legacy.env"
printf '%s\n' \
    'SNP_GO_TOOLCHAIN="go1.26.5"' \
    "SNP_CA_IMAGE=\"${OLD_CA}\"" >"${LEGACY_PINS}"
snp_load_app_pins "${LEGACY_PINS}"
[[ "${SNP_TEE_GO_TOOLCHAIN}" == go1.26.5 ]]
[[ "${SNP_CA_IMAGE}" == "${OLD_CA}" ]]

assert_rejected_unchanged() {
    local name="$1" contents="$2" invalid
    invalid="${TEST_DIR}/${name}.env"
    printf '%s' "${contents}" >"${invalid}"
    SNP_TEE_GO_TOOLCHAIN="sentinel-toolchain"
    SNP_CA_IMAGE="sentinel-ca"
    if snp_load_app_pins "${invalid}" 2>/dev/null; then
        echo "accepted invalid app pins: ${name}" >&2
        exit 1
    fi
    [[ "${SNP_TEE_GO_TOOLCHAIN}" == sentinel-toolchain ]]
    [[ "${SNP_CA_IMAGE}" == sentinel-ca ]]
}

VALID_CA_LINE="SNP_CA_IMAGE=\"${OLD_CA}\""
VALID_GO_LINE='SNP_TEE_GO_TOOLCHAIN="go1.26.5"'
assert_rejected_unchanged missing-go "${VALID_CA_LINE}"$'\n'
assert_rejected_unchanged missing-ca "${VALID_GO_LINE}"$'\n'
assert_rejected_unchanged empty-go $'SNP_TEE_GO_TOOLCHAIN=""\n'"${VALID_CA_LINE}"$'\n'
assert_rejected_unchanged empty-ca "${VALID_GO_LINE}"$'\nSNP_CA_IMAGE=""\n'
assert_rejected_unchanged duplicate-go "${VALID_GO_LINE}"$'\n'"${VALID_GO_LINE}"$'\n'"${VALID_CA_LINE}"$'\n'
assert_rejected_unchanged duplicate-legacy-go $'SNP_GO_TOOLCHAIN="go1.26.5"\nSNP_GO_TOOLCHAIN="go1.26.5"\n'"${VALID_CA_LINE}"$'\n'
assert_rejected_unchanged both-go-names "${VALID_GO_LINE}"$'\nSNP_GO_TOOLCHAIN="go1.26.5"\n'"${VALID_CA_LINE}"$'\n'
assert_rejected_unchanged duplicate-ca "${VALID_GO_LINE}"$'\n'"${VALID_CA_LINE}"$'\n'"${VALID_CA_LINE}"$'\n'
assert_rejected_unchanged auto-go $'SNP_TEE_GO_TOOLCHAIN="auto"\n'"${VALID_CA_LINE}"$'\n'
assert_rejected_unchanged plus-auto-go $'SNP_TEE_GO_TOOLCHAIN="go1.26.6+auto"\n'"${VALID_CA_LINE}"$'\n'
assert_rejected_unchanged junk-go $'SNP_TEE_GO_TOOLCHAIN="go1.26.6-junk"\n'"${VALID_CA_LINE}"$'\n'
assert_rejected_unchanged mutable-ca "${VALID_GO_LINE}"$'\nSNP_CA_IMAGE="alpine:latest"\n'
assert_rejected_unchanged short-ca "${VALID_GO_LINE}"$'\nSNP_CA_IMAGE="alpine@sha256:abcd"\n'
assert_rejected_unchanged nonhex-ca "${VALID_GO_LINE}"$'\nSNP_CA_IMAGE="alpine@sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"\n'
assert_rejected_unchanged junk-ca "${VALID_GO_LINE}"$'\n'"${VALID_CA_LINE}-junk"$'\n'

echo "SNP application pin selection tests passed"

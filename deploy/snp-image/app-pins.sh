#!/bin/bash

# Read the two inputs measured into an SNP application bundle from the
# application source tree. Keep this separate from the current base pins: an
# historical app rebuild must not replace loader, kernel, or base-image inputs.
snp_read_app_pin() {
    local pins_file="$1" pin_name="$2" matches value
    [[ -r "${pins_file}" ]] || {
        echo "ERROR: cannot read SNP app pins: ${pins_file}" >&2
        return 1
    }
    matches="$(grep -Ec "^${pin_name}=\"[^\"]+\"$" "${pins_file}" || true)"
    [[ "${matches}" == 1 ]] || {
        echo "ERROR: expected one quoted ${pin_name} assignment in ${pins_file}" >&2
        return 1
    }
    value="$(sed -n "s/^${pin_name}=\"\([^\"]*\)\"$/\1/p" "${pins_file}")"
    [[ -n "${value}" ]] || {
        echo "ERROR: empty ${pin_name} in ${pins_file}" >&2
        return 1
    }
    printf '%s\n' "${value}"
}

snp_read_toolchain_pin() {
    local pins_file="$1" current_count legacy_count
    current_count="$(grep -Ec '^SNP_TEE_GO_TOOLCHAIN=' "${pins_file}" || true)"
    legacy_count="$(grep -Ec '^SNP_GO_TOOLCHAIN=' "${pins_file}" || true)"
    if [[ "${current_count}" == 1 && "${legacy_count}" == 0 ]]; then
        snp_read_app_pin "${pins_file}" SNP_TEE_GO_TOOLCHAIN
        return
    fi
    if [[ "${current_count}" == 0 && "${legacy_count}" == 1 ]]; then
        snp_read_app_pin "${pins_file}" SNP_GO_TOOLCHAIN
        return
    fi
    echo "ERROR: expected exactly one quoted SNP_TEE_GO_TOOLCHAIN or SNP_GO_TOOLCHAIN assignment in ${pins_file}" >&2
    return 1
}

snp_load_app_pins() {
    local pins_file="$1" tee_toolchain ca_image
    tee_toolchain="$(snp_read_toolchain_pin "${pins_file}")" || return
    ca_image="$(snp_read_app_pin "${pins_file}" SNP_CA_IMAGE)" || return
    [[ "${tee_toolchain}" =~ ^go1\.[0-9]+\.[0-9]+$ ]] || {
        echo "ERROR: invalid SNP_TEE_GO_TOOLCHAIN in ${pins_file}" >&2
        return 1
    }
    [[ "${ca_image}" =~ ^alpine@sha256:[0-9a-f]{64}$ ]] || {
        echo "ERROR: invalid SNP_CA_IMAGE in ${pins_file}" >&2
        return 1
    }

    # Publish both values only after both have passed exact validation.
    SNP_TEE_GO_TOOLCHAIN="${tee_toolchain}"
    SNP_CA_IMAGE="${ca_image}"
}

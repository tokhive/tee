#!/bin/bash

snp_require_source_commit() {
    local repo_root="$1" source_commit="$2" resolved
    [[ "${source_commit}" =~ ^[0-9a-f]{40}$ ]] || {
        echo "ERROR: SNP_BUILD_COMMIT must be an exact lowercase 40-hex commit ID" >&2
        return 1
    }
    resolved="$(git -C "${repo_root}" rev-parse --verify --end-of-options "${source_commit}^{commit}" 2>/dev/null)" || {
        echo "ERROR: SNP_BUILD_COMMIT is not a commit object in this repository" >&2
        return 1
    }
    [[ "${resolved}" == "${source_commit}" ]] || {
        echo "ERROR: SNP_BUILD_COMMIT did not resolve to the exact requested commit" >&2
        return 1
    }
}

snp_checkout_source_commit() {
    local repo_root="$1" source_commit="$2" clone_dir="$3" checked_out
    snp_require_source_commit "${repo_root}" "${source_commit}" || return
    git clone -q -- "${repo_root}" "${clone_dir}"
    git -C "${clone_dir}" checkout -q --detach "${source_commit}"
    checked_out="$(git -C "${clone_dir}" rev-parse --verify HEAD)"
    [[ "${checked_out}" == "${source_commit}" ]] || {
        echo "ERROR: detached app checkout does not match SNP_BUILD_COMMIT" >&2
        return 1
    }
}

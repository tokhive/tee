# Throwaway image-build environment for the two-tier SEV-SNP image (base UKI +
# app partition). Uses ukify + systemd-repart (two-tier UKI, no full-OS rootfs). Run
# privileged with /dev mounted for the loop-free systemd-repart disk assembly.
# Base images and the Ubuntu archive snapshot are pinned so a rebuild cannot
# drift when live APT repositories supersede a package. Defaults match pins.env.
ARG CA_IMAGE=alpine@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
ARG UBUNTU_DIGEST=sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

# Ubuntu's minimal image has no TLS roots, but the official snapshot service
# uses HTTPS. Bootstrap trust comes from the digest-pinned current base CA that
# snp-build.sh passes here; historical app CA pins do not alter this base input.
# Ubuntu's ca-certificates package replaces this file below.
FROM ${CA_IMAGE} AS apt-tls

FROM ubuntu:24.04@${UBUNTU_DIGEST}
COPY --from=apt-tls /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV DEBIAN_FRONTEND=noninteractive

ARG APT_SNAPSHOT=20260821T133530Z
# APT source for the two-tier image build: "snapshot" reproduces an immutable
# Ubuntu snapshot (default, deterministic base); "aliyun" uses the live Aliyun
# mirror (CN-friendly fallback when snapshot.ubuntu.com is blocked or flaky via
# a local proxy). Only the diagnostic base digest changes — the trust root (R)
# and the app bundle digest are unaffected.
ARG APT_MIRROR=snapshot

# Cloud-specific kernel: linux-image-gcp or linux-image-aws. Each ships a few
# non-builtin modules the loader bundles+inserts (gve on GCP, sev-guest on AWS).
ARG KERNEL_PKG=linux-image-gcp

# Every tool whose output lands in the measured base UKI is version-pinned
# (snp-image/pins.env -> these build-args): the stub + ukify build it, zstd/cpio
# compress+archive the initrd, binutils backs ukify's PE assembly, systemd ships
# systemd-measure. dosfstools/mtools/python3 only touch the unmeasured disk.
ARG SYSTEMD_BOOT_VER=255.4-1ubuntu8.17
ARG SYSTEMD_UKIFY_VER=255.4-1ubuntu8.17
ARG SYSTEMD_VER=255.4-1ubuntu8.17
ARG ZSTD_VER=1.5.5+dfsg2-2build1.1
ARG CPIO_VER=2.15+dfsg-1ubuntu2
ARG BINUTILS_VER=2.42-4ubuntu2.10
ARG SBSIGNTOOL_VER=0.9.4-3.1ubuntu7
ARG EFITOOLS_VER=1.9.2-3ubuntu3
RUN if [ "${APT_MIRROR}" = "aliyun" ]; then \
        sed -i \
          -e "s#http://archive.ubuntu.com/ubuntu/#https://mirrors.aliyun.com/ubuntu/#" \
          -e "s#http://security.ubuntu.com/ubuntu/#https://mirrors.aliyun.com/ubuntu/#" \
          /etc/apt/sources.list.d/ubuntu.sources; \
    else \
        sed -i \
          -e "s#http://archive.ubuntu.com/ubuntu/#https://snapshot.ubuntu.com/ubuntu/${APT_SNAPSHOT}/#" \
          -e "s#http://security.ubuntu.com/ubuntu/#https://snapshot.ubuntu.com/ubuntu/${APT_SNAPSHOT}/#" \
          /etc/apt/sources.list.d/ubuntu.sources; \
    fi \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        "systemd=${SYSTEMD_VER}" \
        "systemd-boot-efi=${SYSTEMD_BOOT_VER}" "systemd-ukify=${SYSTEMD_UKIFY_VER}" \
        dosfstools mtools \
        "zstd=${ZSTD_VER}" "cpio=${CPIO_VER}" "binutils=${BINUTILS_VER}" \
        "sbsigntool=${SBSIGNTOOL_VER}" "efitools=${EFITOOLS_VER}" \
        "${KERNEL_PKG}" ca-certificates \
        python3 \
    && rm -rf /var/lib/apt/lists/*

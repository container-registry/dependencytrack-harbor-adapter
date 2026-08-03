# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the waybill Harbor scanner adapter.
#
# The adapter binary, the lprobe healthcheck binary, and the waybill CLI are all
# staged on the host into bin/linux-<arch>/ by `task build`, `task build:lprobe`,
# and `task build:waybill`, then COPY'd in (no Go build stage, so multi-arch needs
# no Go-under-QEMU). waybill comes from its checksum-verified public release
# tarball rather than ghcr.io/kusari-oss/waybill, which is a private package; the
# binaries are identical. The final base is glibc-based distroless: waybill
# releases are *-unknown-linux-gnu, so alpine/musl/static bases are wrong.

# Digest-pinned distroless cc-debian12:nonroot (glibc + libssl + ca-certificates,
# nonroot uid 65532, no shell). BASE_IMAGE is passed by `task image` from versions.env.
# ARGs consumed by a FROM must be declared before the first FROM.
ARG BASE_IMAGE=gcr.io/distroless/cc-debian12:nonroot

# ---- final image -----------------------------------------------------------------
FROM ${BASE_IMAGE}

ARG TARGETARCH

LABEL org.opencontainers.image.title="waybill-harbor-adapter" \
      org.opencontainers.image.description="Harbor Pluggable Scanner Adapter that generates SBOMs using waybill" \
      org.opencontainers.image.source="https://github.com/container-registry/waybill-harbor-adapter" \
      org.opencontainers.image.licenses="Apache-2.0"

# waybill CLI (Apache-2.0) plus its LICENSE, redistributed unmodified (see NOTICE).
COPY bin/linux-${TARGETARCH}/waybill /usr/local/bin/waybill
COPY bin/linux-${TARGETARCH}/waybill-LICENSE /licenses/waybill-LICENSE

# Healthcheck probe (distroless has no shell/curl) and the adapter binary.
COPY bin/linux-${TARGETARCH}/lprobe /usr/local/bin/lprobe
COPY bin/linux-${TARGETARCH}/scanner-waybill /usr/local/bin/scanner-waybill

# Establish the per-job work-dir root owned by the nonroot uid. In production this
# path is mounted writable (K8s emptyDir / compose tmpfs) over a read-only root FS.
# The mode here does NOT survive a mount: a tmpfs mounted over this directory gets
# the daemon's default mode, not this one (Docker Desktop happens to give 1777, the
# Linux engine does not). Every mount site must therefore say so itself: compose
# needs `mode=1777`, K8s needs `fsGroup: 65532`. This chown/chmod only covers the
# unmounted case, e.g. `docker run` with no volume at all.
COPY --chown=65532:65532 --chmod=1777 image/home-scanner/ /home/scanner/

# Runtime env. Deliberately NO WAYBILL_* here: the adapter reports the waybill
# version by exec'ing `waybill --version` at startup, and the waybill subprocess
# env is built as an explicit allowlist by the wrapper (M3), not inherited.
ENV HOME=/home/scanner \
    SCANNER_WAYBILL_WORK_DIR=/home/scanner/work

USER nonroot

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/lprobe", "-mode=http", "-port=8080", "-endpoint=/probe/healthy"]

ENTRYPOINT ["/usr/local/bin/scanner-waybill"]

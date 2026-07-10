# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the mikebom Harbor scanner adapter.
#
# The adapter binary, the lprobe healthcheck binary, and the mikebom CLI are all
# staged on the host into bin/linux-<arch>/ by `task build`, `task build:lprobe`,
# and `task build:mikebom`, then COPY'd in (no Go build stage, so multi-arch needs
# no Go-under-QEMU). mikebom comes from its checksum-verified public release
# tarball rather than ghcr.io/kusari-oss/mikebom, which is a private package; the
# binaries are identical. The final base is glibc-based distroless: mikebom
# releases are *-unknown-linux-gnu, so alpine/musl/static bases are wrong.

# Digest-pinned distroless cc-debian12:nonroot (glibc + libssl + ca-certificates,
# nonroot uid 65532, no shell). BASE_IMAGE is passed by `task image` from versions.env.
# ARGs consumed by a FROM must be declared before the first FROM.
ARG BASE_IMAGE=gcr.io/distroless/cc-debian12:nonroot

# ---- final image -----------------------------------------------------------------
FROM ${BASE_IMAGE}

ARG TARGETARCH

LABEL org.opencontainers.image.title="mikebom-harbor-adapter" \
      org.opencontainers.image.description="Harbor Pluggable Scanner Adapter that generates SBOMs using mikebom" \
      org.opencontainers.image.source="https://github.com/container-registry/mikebom-harbor-adapter" \
      org.opencontainers.image.licenses="Apache-2.0"

# mikebom CLI (Apache-2.0) plus its LICENSE, redistributed unmodified (see NOTICE).
COPY bin/linux-${TARGETARCH}/mikebom /usr/local/bin/mikebom
COPY bin/linux-${TARGETARCH}/mikebom-LICENSE /licenses/mikebom-LICENSE

# Healthcheck probe (distroless has no shell/curl) and the adapter binary.
COPY bin/linux-${TARGETARCH}/lprobe /usr/local/bin/lprobe
COPY bin/linux-${TARGETARCH}/scanner-mikebom /usr/local/bin/scanner-mikebom

# Establish the per-job work-dir root owned by the nonroot uid. In production this
# path is mounted writable (K8s emptyDir / compose tmpfs) over a read-only root FS.
# Mode 1777 (sticky, like /tmp): a Docker/compose tmpfs mounted over an existing
# directory inherits that directory's mode but resets ownership to root, so 1777 is
# what keeps the mount writable by uid 65532 without a per-run tmpfs mode override.
COPY --chown=65532:65532 --chmod=1777 image/home-scanner/ /home/scanner/

# Runtime env. Deliberately NO MIKEBOM_* here: the adapter reports the mikebom
# version by exec'ing `mikebom --version` at startup, and the mikebom subprocess
# env is built as an explicit allowlist by the wrapper (M3), not inherited.
ENV HOME=/home/scanner \
    SCANNER_MIKEBOM_WORK_DIR=/home/scanner/work

USER nonroot

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/lprobe", "-mode=http", "-port=8080", "-endpoint=/probe/healthy"]

ENTRYPOINT ["/usr/local/bin/scanner-mikebom"]

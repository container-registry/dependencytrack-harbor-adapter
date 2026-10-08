# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the Dependency-Track Harbor scanner adapter.
#
# The adapter binary, the healthprobe healthcheck binary, and the syft CLI are all
# staged on the host into bin/linux-<arch>/ by `task build`, `task build:healthprobe`,
# and `task build:syft`, then COPY'd in. No Go build stage, so multi-arch needs no
# Go-under-QEMU. syft comes from its checksum-verified public release tarball.
#
# The base is glibc-based distroless because syft's release binaries are
# dynamically linked; an alpine/musl or static base cannot run them.

# Digest-pinned distroless cc-debian12:nonroot (glibc + libssl + ca-certificates,
# nonroot uid 65532, no shell). BASE_IMAGE is passed by `task image` from
# versions.env. ARGs consumed by a FROM must be declared before the first FROM.
# Digest-pinned so a direct `docker build` has the same provenance as `task image`.
# A bare :nonroot tag is mutable, so the two paths could otherwise produce images
# with different bases. Keep in sync with DISTROLESS_* in versions.env.
ARG BASE_IMAGE=gcr.io/distroless/cc-debian12:nonroot@sha256:ce0d66bc0f64aae46e6a03add867b07f42cc7b8799c949c2e898057b7f75a151

# ---- final image -----------------------------------------------------------------
FROM ${BASE_IMAGE}

ARG TARGETARCH

LABEL org.opencontainers.image.title="dependencytrack-harbor-adapter" \
      org.opencontainers.image.description="Harbor Pluggable Scanner Adapter that generates SBOMs and feeds them to Dependency-Track" \
      org.opencontainers.image.source="https://github.com/container-registry/dependencytrack-harbor-adapter" \
      org.opencontainers.image.licenses="Apache-2.0"

# syft CLI (Apache-2.0) plus its LICENSE, redistributed unmodified (see NOTICE).
COPY bin/linux-${TARGETARCH}/syft /usr/local/bin/syft
COPY bin/linux-${TARGETARCH}/syft-LICENSE /licenses/syft-LICENSE

# Healthcheck probe (distroless has no shell/curl) and the adapter binary.
COPY bin/linux-${TARGETARCH}/healthprobe /usr/local/bin/healthprobe
COPY bin/linux-${TARGETARCH}/scanner-dependencytrack /usr/local/bin/scanner-dependencytrack

# Establish the per-job work-dir root owned by the nonroot uid. In production this
# path is mounted writable (K8s emptyDir / compose tmpfs) over a read-only root FS.
# The mode here does NOT survive a mount: a tmpfs mounted over this directory gets
# the daemon's default mode, not this one (Docker Desktop happens to give 1777, the
# Linux engine does not). Every mount site must therefore say so itself: compose
# needs `mode=1777`, K8s needs `fsGroup: 65532`. This chown/chmod only covers the
# unmounted case, e.g. `docker run` with no volume at all.
COPY --chown=65532:65532 --chmod=1777 image/home-scanner/ /home/scanner/

# Runtime env. Deliberately NO SYFT_* here: syft reads SYFT_* as its own
# configuration, and the subprocess environment is built as an explicit allowlist
# by the wrapper rather than inherited from this image.
ENV HOME=/home/scanner \
    SCANNER_SYFT_WORK_DIR=/home/scanner/work

USER nonroot

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/healthprobe", "-mode=http", "-port=8080", "-endpoint=/probe/healthy"]

ENTRYPOINT ["/usr/local/bin/scanner-dependencytrack"]

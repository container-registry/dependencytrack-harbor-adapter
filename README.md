# dependencytrack-harbor-adapter

A [Harbor](https://goharbor.io) Pluggable Scanner Adapter that keeps a
[Dependency-Track](https://dependencytrack.org) portfolio in sync with what is
actually in your registry.

For each artifact Harbor asks it to scan, the adapter produces an SBOM, hands the
SPDX document back to Harbor, and uploads the same inventory to Dependency-Track
as CycloneDX. It advertises exactly one capability: `type: "sbom"`.

> [!WARNING]
> This adapter generates SBOMs. It has **no vulnerability scanner** of its own.
> It must **complement**, not replace, a vulnerability scanner (such as Trivy) in
> a Harbor deployment. Registering it as a project's only scanner leaves that
> project with no vulnerability scanning at all.
>
> That is by design. Dependency-Track does its own correlation: it mirrors NVD,
> OSV, GitHub Advisories and EPSS and re-analyzes the whole portfolio daily. It
> wants the component list, not a scanner's findings.

## How it works

```
Harbor ──POST /api/v1/scan──▶ adapter
                                │
                                ├─1─ referrers lookup for an existing Harbor SBOM
                                │     ├── hit  → fetch ~40 KB accessory, no image pull
                                │     └── miss → syft pulls and scans the image
                                │
                                ├─2─ SPDX 2.3 ─────────▶ returned to Harbor
                                └─3─ CycloneDX 1.6 ────▶ PUT /api/v1/bom (Dependency-Track)
```

### The fast path, and when it actually fires

Harbor stores an SBOM it generated as an OCI *accessory*: a referrer of the image
with artifact type `application/vnd.goharbor.harbor.sbom.v1`. When one exists,
this adapter reuses it instead of pulling the image, which turns a
multi-gigabyte pull into a referrers call and a ~40 KB blob GET.

> [!IMPORTANT]
> **On Harbor's own SBOM scan path, this never fires, and that is Harbor's
> behaviour rather than a bug here.** Before dispatching an SBOM scan Harbor
> deletes every existing SBOM accessory on the artifact
> (`scanHandler.deleteSBOMAccessory`, `src/pkg/scan/sbom/sbom.go`), and only
> pushes the new one once the scan returns. Measured on Harbor 2.16: the
> accessory count for an artifact goes 1 → 0 within 3 seconds of triggering a
> scan and back to 1 about 9 seconds later, which is exactly the window the
> adapter runs in.
>
> So a deployment where Harbor drives every scan will show
> `sbom_reused_total` at zero and `sbom_generated_total` climbing. That is
> correct, not broken.

The path is kept because it is cheap (one referrers call), correct, and does
fire whenever the adapter is invoked outside Harbor's SBOM scan flow, which is
the case for a rescan of an artifact whose accessory Harbor did not clear. If
the goal is specifically to avoid image pulls by reusing Harbor's own SBOMs,
a `SCANNING_COMPLETED` webhook consumer is the right shape: that event fires
*after* the accessory is pushed, not before it is deleted.

Two things about those accessories are not obvious and are load-bearing:

- The accessory manifest carries **no top-level `artifactType`**. Harbor sets the
  type as the manifest's `config.mediaType`, and registries synthesize
  `artifactType` from it in referrers responses. So the value being filtered on
  appears nowhere in the manifest itself.
- The single layer is declared `application/vnd.oci.image.layer.v1.tar` but is
  **not a tar**. It is the raw SBOM JSON. Untarring it fails.

Both were confirmed against Harbor 2.16 by pulling an accessory and comparing it
byte for byte with the same document served from Harbor's REST API.

Every failure in the lookup is non-fatal: no accessory, no referrers support, an
unreadable blob, a timeout, all fall back to generating.

### Why syft, and why CycloneDX 1.6

syft emits SPDX 2.3 and CycloneDX 1.6 from a **single scan**, and converts
between them offline for the fast path. One pull, both formats, no lossy
round-trip through a third tool.

The CycloneDX version is pinned, not defaulted. Dependency-Track validates every
uploaded BOM against the CycloneDX schemas bundled in `cyclonedx-core-java`,
which ship `bom-1.0` through `bom-1.6`. A 1.7 document, which several current
SBOM tools emit by default, has no schema to validate against and is rejected
with an RFC 9457 problem document. The pin is a compatibility contract.

File cataloging is disabled (`SYFT_FILE_METADATA_SELECTION=none`). With it on,
syft emits one CycloneDX component per file, none carrying a purl: on a small
Alpine image that is 234 file components against 18 real packages, all of which
Dependency-Track would store and render while being able to analyze none.

### How artifacts map onto Dependency-Track projects

Dependency-Track keys projects by **name and version**. Harbor gives the adapter
a repository and a digest, and no tag. So:

| Dependency-Track | Value |
|---|---|
| `projectName` | the Harbor repository, e.g. `library/alpine` |
| `projectVersion` | the artifact digest |
| `parentName` | the Harbor project (first path segment), unless disabled |
| `isLatest` | always set: the newest artifact the adapter has seen wins |
| `autoCreate` | always on |

One project version per image build is unbounded growth over time, and it is
deliberate: the digest is the only identity Harbor actually supplies, and
inventing a stable one from a mutable tag would silently overwrite the history of
what was deployed.

## Configuration

All configuration is environment variables.

| Variable | Default | Purpose |
|---|---|---|
| `SCANNER_DTRACK_URL` | — | Dependency-Track API root. Empty disables uploads (warns at startup) |
| `SCANNER_DTRACK_API_KEY` | — | Team API key with `BOM_UPLOAD` **and** `PROJECT_CREATION_UPLOAD` |
| `SCANNER_DTRACK_TIMEOUT` | `60s` | Per-upload timeout |
| `SCANNER_DTRACK_PROJECT_TAGS` | `harbor` | Tags applied to projects this adapter creates |
| `SCANNER_DTRACK_NEST_UNDER_HARBOR_PROJECT` | `true` | File repositories under a parent named for the Harbor project |
| `SCANNER_DTRACK_FAIL_SCAN_ON_UPLOAD_ERROR` | `false` | Whether a failed upload fails the Harbor scan |
| `SCANNER_DTRACK_INSECURE_TLS_SKIP_VERIFY` | `false` | Dev/CI only |
| `SCANNER_SYFT_BINARY` | `/usr/local/bin/syft` | syft CLI path |
| `SCANNER_SYFT_WORK_DIR` | `/home/scanner/work` | Per-job scratch root; must be writable |
| `SCANNER_SYFT_TIMEOUT` | `5m0s` | Per-scan timeout; also derives the job lock TTL. Must be positive |
| `SCANNER_SYFT_REGISTRY_CA_CERT` | — | PEM bundle trusted for the registry pull |
| `SCANNER_SYFT_INSECURE_TLS_SKIP_VERIFY` | `false` | Dev/CI only |
| `SCANNER_SYFT_IMAGE_PLATFORM` | — | Override the platform resolved from a multi-arch index |
| `SCANNER_SYFT_EXTRA_ARGS` | — | Space-separated extra syft flags |
| `SCANNER_SYFT_MAX_IMAGE_SIZE` | `1073741824` (1 GiB) | Reject artifacts larger than this before the pull. `0` disables. Memory guard, see below |

Plus `SCANNER_API_SERVER_*` (listener and TLS), `SCANNER_API_AUTH_API_KEY`,
`SCANNER_STORE_BACKEND` (`redis` or `memory`), `SCANNER_STORE_REDIS_*`,
`SCANNER_JOB_QUEUE_REDIS_*`, `SCANNER_REDIS_*` and `SCANNER_LOG_LEVEL`. See
`pkg/etc/config.go`; unusable combinations are rejected at startup rather than at
scan time. `SCANNER_DTRACK_URL` and `SCANNER_DTRACK_API_KEY` must be set together.

### What a failed upload does

By default, nothing to the scan. The SBOM is Harbor's deliverable and it is
already generated; discarding it because a third system was briefly unreachable
would make the adapter strictly less useful than one without the integration. The
failure is logged and counted in `bom_upload_failures_total`.

The cost of that default is that **Harbor looks entirely healthy while the
Dependency-Track portfolio silently stops being updated**, so that counter is the
one to alert on. Set `SCANNER_DTRACK_FAIL_SCAN_ON_UPLOAD_ERROR=true` where a
visible failed scan is preferable to a silent gap.

## Metrics

`GET /metrics` (Prometheus text format, enabled by `SCANNER_API_SERVER_METRICS_ENABLED`,
default on). Alongside the Go runtime defaults:

| Metric | Type | Notes |
|---|---|---|
| `harbor_scanner_dependencytrack_scans_total` | counter | Labels `outcome` (`success`/`failure`) and `category` |
| `harbor_scanner_dependencytrack_scan_duration_seconds` | histogram | Label `outcome`; buckets reach 1800s |
| `harbor_scanner_dependencytrack_sbom_reused_total` | counter | Scans served from an existing Harbor SBOM, no image pull |
| `harbor_scanner_dependencytrack_sbom_generated_total` | counter | Scans that pulled the image |
| `harbor_scanner_dependencytrack_accessory_fetch_failures_total` | counter | Fast-path lookups that errored (a miss is not counted) |
| `harbor_scanner_dependencytrack_bom_uploads_total` | counter | BOMs accepted by Dependency-Track |
| `harbor_scanner_dependencytrack_bom_upload_failures_total` | counter | BOMs rejected or never delivered |
| `harbor_scanner_dependencytrack_queue_wait_seconds` | histogram | Enqueue to pickup |
| `harbor_scanner_dependencytrack_queue_depth` | gauge | Jobs waiting; `NaN` when the queue cannot be read |
| `harbor_scanner_dependencytrack_scans_in_flight` | gauge | Scans executing in this process |
| `harbor_scanner_dependencytrack_enqueued_total` | counter | Jobs accepted |
| `harbor_scanner_dependencytrack_enqueue_failures_total` | counter | Requests that could not be queued |
| `harbor_scanner_dependencytrack_report_stored_bytes` | histogram | Stored (compressed) envelope size |
| `harbor_scanner_dependencytrack_image_compressed_bytes` | histogram | Artifact size as read from its manifest |
| `harbor_scanner_dependencytrack_image_probe_failures_total` | counter | Size checks that failed; those scans ran unguarded |

`category` is the `syft.ErrorCategory` of the failure, which is the label that
separates a broken scanner from a misconfigured registration:
`RegistryPullAuth` (credentials rejected), `RegistryPullTransport` (TLS or
scheme), `RegistryPull`, `Timeout`, `SyftExec`, plus `Adapter` for failures the
adapter raised itself, `Expired` for a job that waited longer than
`SCANNER_STORE_REDIS_SCAN_JOB_TTL`, and `ImageTooLarge` for one refused by the
pre-pull size cap.

**Memory is the binding constraint on the generation path.** Pulling and
cataloging an image holds layer content in memory, and an OOM kills the
container rather than the job, so one oversized artifact takes every in-flight
scan with it. `SCANNER_SYFT_MAX_IMAGE_SIZE` prevents that, but only in step with
the container memory limit — raising the cap alone just moves the OOM back one
artifact. This is also why `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY` defaults to
`1`: scale with replicas, since concurrency multiplies peak memory.

The fast path does not pull anything, so it is not subject to this at all. The
more of your traffic it serves, the less this section matters.

Worth alerting on: `bom_upload_failures_total` (see above), any
`category="Expired"` (jobs aging out of the store before a worker reaches them),
and a rising `queue_wait_seconds` (the worker pool is too small for the rate
Harbor dispatches at).

`/metrics` is served outside the `/api/v1` prefix, so `SCANNER_API_AUTH_API_KEY`
does not protect it. Keep it off the ingress.

## Development

Requires Go (see `go.mod`), [Task](https://taskfile.dev), and Docker.

```
task              # build the adapter binary (native arch)
task test         # unit tests with race + coverage
task lint:local   # golangci-lint (pinned)
task image:local  # build the container image locally (--load, native arch)
task dev:up       # local harness: redis + adapter over one compose network
task info         # print version and tool pins
```

Version pins (syft CLI, base image, and dev tooling) live in `versions.env`, the
single source of truth loaded by the Taskfile and CI.

## Relationship to waybill-harbor-adapter

This is a hard fork of
[waybill-harbor-adapter](https://github.com/container-registry/waybill-harbor-adapter),
which shares its Harbor API v1 implementation, job queue, Redis store, metrics
and memory guard. What is new here is the accessory fast path (`pkg/accessory`),
the Dependency-Track client (`pkg/dtrack`), and a syft wrapper that emits both
formats from one scan (`pkg/syft`).

## License

Apache-2.0 (see [LICENSE](LICENSE)). The container image bundles the syft binary
under Apache-2.0; see [NOTICE](NOTICE).

# waybill-harbor-adapter

A [Harbor](https://goharbor.io) Pluggable Scanner Adapter that generates Software
Bill of Materials (SBOM) documents for container images using
[waybill](https://github.com/kusari-oss/waybill), the Kusari Rust SBOM CLI.

It implements the Harbor Scanner Adapter API v1 so Harbor can invoke it as a
pluggable scanner. It advertises exactly one capability: `type: "sbom"`.

> [!WARNING]
> waybill generates SBOMs only. It has **no vulnerability scanner**. This adapter
> must **complement**, not replace, a vulnerability scanner (such as Trivy) in a
> Harbor deployment. Registering it as the sole scanner leaves a project with no
> vulnerability scanning at all.

## How it works

The adapter turns a Harbor scan request into one `waybill` invocation. waybill
pulls the artifact from Harbor's registry itself and scans it in the same process:

```
waybill --offline --timeout <n> sbom scan \
  --image core:8080/library/alpine@sha256:... \
  --image-src remote \
  --format spdx-2.3-json --output spdx-2.3-json=<workdir>/report.spdx.json \
  --insecure-registry core:8080 \
  --no-oci-cache
```

`--image-src remote` is pinned rather than defaulted: waybill's default order is
`docker,podman,remote`, and the image ships no container runtime to probe.

Registry transport is derived from the scan request and configuration:

| Situation | What the adapter passes |
|---|---|
| `registry.url` scheme is `http` | `--insecure-registry <host:port>` |
| Registry behind a private CA | `--registry-ca-cert <path>` per `SCANNER_WAYBILL_REGISTRY_CA_CERTS` |
| Self-signed dev/CI certs | `--insecure-tls-skip-verify` per `SCANNER_WAYBILL_INSECURE_TLS_SKIP_VERIFY` |

Credentials (Basic, decoded from the scan request; anonymous when the header is
empty) are passed through the environment as
`WAYBILL_REGISTRY_<HOST>_USERNAME`/`_PASSWORD`, never through argv — argv is
readable by anything that can stat `/proc/<pid>/cmdline`.

Enrichment network calls (deps.dev, ClearlyDefined) are disabled with the
`--offline` CLI flag; the env var alone does not disable them (see
`docs/spike-m1.md`). `--offline` does not affect the registry pull.

Earlier revisions pulled the artifact themselves with go-containerregistry and
handed waybill a docker-save tarball, because waybill's OCI client hardcoded
`https://` and trusted only webpki roots. waybill milestone 182 fixed both; see
`docs/upstream-issues.md`.

## Configuration

All configuration is environment variables. The scanner-facing ones:

| Variable | Default | Purpose |
|---|---|---|
| `SCANNER_WAYBILL_BINARY` | `/usr/local/bin/waybill` | waybill CLI path |
| `SCANNER_WAYBILL_WORK_DIR` | `/home/scanner/work` | Per-job scratch root; must be writable and sized |
| `SCANNER_WAYBILL_TIMEOUT` | `5m0s` | Per-scan timeout; also derives the job lock TTL. Must be positive |
| `SCANNER_WAYBILL_REGISTRY_CA_CERTS` | — | Comma-separated PEM bundles trusted for the registry pull |
| `SCANNER_WAYBILL_INSECURE_TLS_SKIP_VERIFY` | `false` | Disable TLS verification for pulls (dev/CI only) |
| `SCANNER_WAYBILL_ENRICHMENT` | `false` | Drop `--offline`, allowing deps.dev / ClearlyDefined egress |
| `SCANNER_WAYBILL_IMAGE_PLATFORM` | — | Override the platform resolved from a multi-arch index |
| `SCANNER_WAYBILL_OCI_CACHE_SIZE` | `0` | Blob-cache cap in bytes; `0` passes `--no-oci-cache` |
| `SCANNER_WAYBILL_EXTRA_ARGS` | — | Space-separated extra waybill flags |
| `SCANNER_WAYBILL_MAX_IMAGE_SIZE` | `536870912` (512 MiB) | Reject artifacts larger than this, before the pull. `0` disables. Memory guard, see below |

Plus `SCANNER_API_SERVER_*` (listener and TLS), `SCANNER_API_AUTH_API_KEY`,
`SCANNER_STORE_BACKEND` (`redis` or `memory`), `SCANNER_STORE_REDIS_*`,
`SCANNER_JOB_QUEUE_REDIS_*`, `SCANNER_REDIS_*` and `SCANNER_LOG_LEVEL`. See
`pkg/etc/config.go`; unusable combinations are rejected at startup rather than at
scan time.

## Metrics

`GET /metrics` (Prometheus text format, enabled by `SCANNER_API_SERVER_METRICS_ENABLED`,
default on). Alongside the Go runtime defaults:

| Metric | Type | Notes |
|---|---|---|
| `harbor_scanner_waybill_scans_total` | counter | Labels `outcome` (`success`/`failure`) and `category` |
| `harbor_scanner_waybill_scan_duration_seconds` | histogram | Label `outcome`; buckets reach 1800s |
| `harbor_scanner_waybill_queue_wait_seconds` | histogram | Enqueue to pickup |
| `harbor_scanner_waybill_queue_depth` | gauge | Jobs waiting; `NaN` when the queue cannot be read |
| `harbor_scanner_waybill_scans_in_flight` | gauge | Scans executing in this process |
| `harbor_scanner_waybill_enqueued_total` | counter | Jobs accepted |
| `harbor_scanner_waybill_enqueue_failures_total` | counter | Requests that could not be queued |
| `harbor_scanner_waybill_report_stored_bytes` | histogram | Stored (compressed) envelope size |
| `harbor_scanner_waybill_image_compressed_bytes` | histogram | Artifact size as read from its manifest |
| `harbor_scanner_waybill_image_probe_failures_total` | counter | Size checks that failed; those scans ran unguarded |

`category` is the `waybill.ErrorCategory` of the failure, which is the label that
separates a broken scanner from a misconfigured registration:
`RegistryPullAuth` (credentials rejected), `RegistryPullTransport` (TLS or scheme),
`RegistryPull`, `Timeout`, `WaybillExec`, plus `Adapter` for failures the adapter
raised itself, `Expired` for a job that waited longer than
`SCANNER_STORE_REDIS_SCAN_JOB_TTL`, and `ImageTooLarge` for one refused by the
pre-pull size cap.

**Memory is the binding constraint.** waybill holds layer content in memory while
pulling, so peak RSS runs at ~4.5x the compressed image size and nothing else
bounds it: `golang:1.24` (316 MB) peaks at 1.32 GiB, `node:22` (400 MB) at
1.65 GiB and OOM-kills a 2Gi container, and a 3.7 GB image is OOM-killed even at
7Gi. Because the kill lands on the container, one oversized artifact takes every
in-flight scan with it.

`SCANNER_WAYBILL_MAX_IMAGE_SIZE` prevents that, but only in step with the
container memory limit:

```
memory limit  >=  4.5 × SCANNER_WAYBILL_MAX_IMAGE_SIZE × SCANNER_JOB_QUEUE_WORKER_CONCURRENCY
```

The 512 MiB default is paired with the 4Gi limit the shipped deployment sets.
Raising the cap alone just moves the OOM back one artifact. This is also why
`SCANNER_JOB_QUEUE_WORKER_CONCURRENCY` defaults to `1` — scale with replicas.
Full measurements are in `docs/INTEGRATION.md`.

Worth alerting on: any `category="Expired"` (jobs are aging out of the store
before a worker reaches them), and a rising `queue_wait_seconds` (the worker pool
is too small for the rate Harbor dispatches at). See `docs/INTEGRATION.md` for the
TTL invariant and the memory sizing rule — raising
`SCANNER_JOB_QUEUE_WORKER_CONCURRENCY` multiplies peak memory, so replicas are
usually the right answer.

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

Version pins (waybill image, base image, and dev tooling) live in `versions.env`,
the single source of truth loaded by the Taskfile and CI.

## License

Apache-2.0 (see [LICENSE](LICENSE)). The container image bundles the waybill
binary under Apache-2.0; see [NOTICE](NOTICE).

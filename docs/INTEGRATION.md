# Integrating waybill-harbor-adapter with Harbor

This adapter implements the Harbor Pluggable Scanner Adapter API v1. It wraps the
[waybill](https://github.com/kusari-oss/waybill) SBOM CLI and advertises exactly one
capability: **`sbom`**.

## READ THIS FIRST: this scanner has NO vulnerability capability

waybill generates SBOMs. It does **not** detect vulnerabilities. This adapter therefore
advertises only the `sbom` capability and **rejects vulnerability scan requests with HTTP
422** (`pkg/http/api/v1/handler.go`).

Consequences you must plan for:

- **Complement, do not replace.** Register this adapter *alongside* a real vulnerability
  scanner (e.g. Trivy). If you remove or replace your vulnerability scanner with this one,
  the project loses vulnerability scanning entirely. There is no CVE detection here.
- In Harbor, an SBOM scan is triggered separately from a vulnerability scan
  (`{"scan_type":"sbom"}`). A project can have one vulnerability scanner and use this
  adapter for SBOM generation.
- The adapter never reports severities, CVEs, or a vulnerability summary. Harbor's
  vulnerability views stay empty unless a separate vulnerability scanner is configured.

## What the adapter advertises (`GET /api/v1/metadata`)

- Capability `type: sbom`
- Consumes:
  - `application/vnd.docker.distribution.manifest.v2+json`
  - `application/vnd.oci.image.manifest.v1+json`
- Produces: `application/vnd.security.sbom.report+json; version=1.0`
- `sbom_media_types: ["application/spdx+json"]` (Harbor core hardcodes SPDX; no CycloneDX)
- `properties["harbor.scanner-adapter/registry-authorization-type"] = "Basic"`
- The adapter's own version is in `properties["org.label-schema.version"]`. The waybill
  CLI version is reported in `scanner.version` (exec'd from `waybill --version` at startup).

## Registering the scanner

Register it as an **additional, non-default** scanner (so it does not displace your
vulnerability scanner):

```sh
curl -sSf -X POST "https://<harbor-host>/api/v2.0/scanners" \
  -H "Content-Type: application/json" \
  -u "<admin-user>:<admin-pass>" \
  -d '{
    "name": "waybill",
    "description": "waybill SBOM generator (no vulnerability scanning)",
    "url": "http://waybill-adapter:8080",
    "disabled": false,
    "use_internal_addr": true
  }'
```

Notes:

- `url` is the in-cluster / in-network address of the adapter. On the Harbor devenv this
  is the compose service name (e.g. `http://waybill-adapter:8080`); in Kubernetes it is
  the Service DNS name.
- If the adapter is protected with `SCANNER_API_AUTH_API_KEY`, register with an
  `Authorization` header instead (`"auth": "Bearer", "access_credential": "<key>"` per
  the Harbor scanner registration schema).
- Do **not** set this scanner as the project/system default if that would remove a
  vulnerability scanner from the default slot.

Bind it to a project (Harbor UI: Project -> Scanner -> select `waybill`), or via the API.

## Triggering an SBOM scan

```sh
curl -sSf -X POST \
  "https://<harbor-host>/api/v2.0/projects/<project>/repositories/<repo>/artifacts/<ref>/scan" \
  -u "<user>:<pass>" \
  -H "Content-Type: application/json" \
  -d '{"scan_type":"sbom"}'
```

Harbor then calls the adapter's `POST /api/v1/scan`, polls
`GET /api/v1/scan/{id}/report` (302 + `Refresh-After` until ready, then 200), and pushes
the resulting SPDX document as an `sbom.harbor` accessory. Download it via the artifact's
`additions/sbom` endpoint or the SBOM tab in the UI.

## How the artifact is pulled

waybill pulls it, via `--image <ref> --image-src remote`. The adapter passes the
reference from the scan request, the transport flags below, and the Basic
credentials (anonymous when the authorization header is empty). Credentials go
through the environment as `WAYBILL_REGISTRY_<HOST>_USERNAME`/`_PASSWORD`, never
through argv.

**Plain-HTTP registries.** A `registry.url` with an `http://` scheme is treated as
insecure automatically and becomes `--insecure-registry <host:port>`. This is why
`use_internal_addr: true` works against the Harbor devenv's `http://core:8080`.

**Private-CA registries.** Set `SCANNER_WAYBILL_REGISTRY_CA_CERTS` to a
comma-separated list of PEM bundle paths mounted into the container; each becomes a
`--registry-ca-cert`. Every path is stat'd at startup, so a wrong path fails the
deployment rather than every scan. Example (K8s):

```yaml
env:
  - name: SCANNER_WAYBILL_REGISTRY_CA_CERTS
    value: /etc/waybill/ca/harbor-ca.pem
volumeMounts:
  - name: registry-ca
    mountPath: /etc/waybill/ca
    readOnly: true
```

`SCANNER_WAYBILL_INSECURE_TLS_SKIP_VERIFY=true` disables chain, hostname and expiry
verification for every pull. It logs a WARN at startup and is for dev/CI against
self-signed certs only — prefer the CA bundle in production.

A pull failure is reported on the job with its cause: `RegistryPullAuth` (the
registry rejected the credentials), `RegistryPullTransport` (TLS or scheme
mismatch — usually a missing `--insecure-registry` or CA bundle), or
`RegistryPull`. Those are configuration problems, distinct from a `WaybillExec`
scanner failure.

**Egress.** waybill runs with `--offline`: it makes no outbound enrichment calls
(deps.dev, ClearlyDefined). See `docs/spike-m1.md` for why the flag, not the
`WAYBILL_OFFLINE` env var, is the real egress control. `--offline` does not affect
the registry pull.

**Disk.** waybill writes its layer scratch and blob cache under the per-job work
dir (`SCANNER_WAYBILL_WORK_DIR`), which the adapter deletes when the job ends and
sweeps at startup. That directory is the bound on a scan's disk use, so give it a
sized mount: `emptyDir.sizeLimit` in K8s, `tmpfs: - /home/scanner:size=...` in
compose. Note disk is not the binding constraint — memory is; see "Memory sizing"
below, and `SCANNER_WAYBILL_MAX_IMAGE_SIZE`, which rejects an oversize artifact up
front rather than letting it fill the mount.

## Observing it

Scrape `GET /metrics`. The series and their meaning are in the README; the two
that answer most integration questions:

- `harbor_scanner_waybill_scans_total{outcome="failure",category=...}` separates a
  broken scanner from a broken registration. A `category` of `RegistryPullAuth` or
  `RegistryPullTransport` is a problem with the scanner registration or the
  registry transport, not with waybill.
- `harbor_scanner_waybill_queue_wait_seconds` against
  `harbor_scanner_waybill_scan_duration_seconds`. If the wait rather than the
  scan is what makes reports late, the worker pool is undersized: add replicas
  or raise `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY` (see the memory sizing rule
  below first), not the scan timeout.
- `harbor_scanner_waybill_scans_total{category="Expired"}` above zero is the hard
  capacity signal: jobs are waiting longer than
  `SCANNER_STORE_REDIS_SCAN_JOB_TTL`, so their records expire before a worker
  reaches them and Harbor's poll 404s.

### How long Harbor will actually wait

Harbor polls the report endpoint every `Refresh-After` seconds and, contrary to a
common reading of its source, does **not** give up after 30 minutes.
`src/pkg/scan/job.go` places `case <-time.After(checkTimeout)` *inside* the
`for { select {...} }`, so a fresh 30-minute timer is created on every iteration
and is discarded on the next 302. (Compare `src/pkg/p2p/preheat/job.go`, which
starts its timer outside the loop and is a real overall timeout.) The 30 minutes
therefore bound the gap between responses, not the total wait, and there is no
jobservice-level cap on a scan job either.

So the effective deadline on a queued job is **this adapter's**
`SCANNER_STORE_REDIS_SCAN_JOB_TTL` (default 1h). Once it elapses the record is
gone, the report GET 404s, and Harbor fails the scan. The invariant to hold is:

```
ScanJobTTL  >  worst-case queue wait  +  worst-case scan duration
```

A job that expires while queued is detected on its first status write, before the
registry pull, so an overloaded adapter does not spend egress and CPU producing
reports with nowhere to go. It is counted as `category="Expired"` rather than as
an adapter or scanner failure.

Note `Refresh-After` is parsed with `strconv.ParseInt(v, 10, 8)`
(`src/pkg/scan/rest/v1/client.go`), so a value above 127 fails to parse and Harbor
silently falls back to 5 seconds.

### Memory sizing

Measured on the devenv (arm64, one scan at a time, disk-backed work dir):

| Image | Compressed | Limit | Result | Peak RSS | Duration |
|---|---|---|---|---|---|
| `alpine:3.20` | 4 MB | 2Gi | 200, 16 packages | 41 MiB | 3s |
| `golang:1.24` | 316 MB | **1Gi** | **OOMKilled**, 500 | 883 MiB (ceiling) | 6s |
| `golang:1.24` | 316 MB | 2Gi | 200, 1355 packages | 1.32 GiB | 40s |
| `golang:1.24` | 316 MB | 4Gi | 200, 1355 packages | 1.28 GiB | 37s |
| `nvidia/cuda:12.6.3-devel` | 3.7 GB | **4Gi** | **OOMKilled**, 500 | 3.68 GiB (ceiling) | 16s |
| `nvidia/cuda:12.6.3-devel` | 3.7 GB | **7Gi** | **OOMKilled**, 500 | 6.94 GiB (ceiling) | 30s |

waybill holds layer content in memory while pulling, so peak tracks image size at
roughly 4x the compressed bytes and is not bounded by anything. The `golang:1.24`
row settles at 1.32 GiB whatever headroom it is given; the cuda rows consume
every byte available and are still killed, which puts their requirement above
7 GiB (~15 GiB by the 4x rule, untestable on a 7.7 GiB Docker VM).

Two consequences:

```
memory limit  ≈  SCANNER_JOB_QUEUE_WORKER_CONCURRENCY  ×  4 × (largest expected compressed image)
```

1. **`SCANNER_JOB_QUEUE_WORKER_CONCURRENCY` stays at `1`.** Raising it multiplies
   the requirement. Scale with replicas, which spread memory across pods.
2. **The pre-pull size cap is what keeps an arbitrary image from OOM-killing the
   pod.** `SCANNER_WAYBILL_MAX_IMAGE_SIZE` (default 512 MiB, `0` disables)
   rejects an artifact whose compressed layers exceed it, before the pull
   allocates anything. Without it the kill lands on the container rather than on
   the one scan, so one oversized image takes every in-flight scan down with it.

   Verified on the devenv at a 2Gi limit: `nvidia/cuda:12.6.3-devel` (3.7 GB)
   returns HTTP 500 with `OOMKilled=false` and the container survives, while
   `golang:1.24` (316 MB) still scans normally.

   ```
   artifact core:8080/library/x@sha256:... is 3710564885 compressed bytes, over the
   536870912 limit; scanning it needs roughly 14842259540 bytes of memory
   (raise SCANNER_WAYBILL_MAX_IMAGE_SIZE and the container memory limit together)
   ```

   The check reads the manifest only, not blobs. For a multi-platform index it
   uses the largest single platform, since waybill pulls one. A probe that
   cannot answer does **not** block the scan: it reaches the same registry over
   the same credentials as the pull, so making every scan depend on it would
   trade a rare OOM for a common outage. Those gaps are counted in
   `harbor_scanner_waybill_image_probe_failures_total` — alert on it, because a
   silently unguarded scanner is worse than no guard.

Also note a `tmpfs` work dir is RAM-backed and charged to the same limit. Use a
disk-backed `emptyDir`, never `emptyDir.medium: Memory`. Alert on
`container_memory_working_set_bytes` against the limit alongside the metrics
above.

## How the report is stored

One Redis key per job key, holding the whole record including the report envelope,
under `SCANNER_STORE_REDIS_SCAN_JOB_TTL` (default 1h).

The record is stored gzipped, because it is almost entirely the SPDX document and
SPDX is highly repetitive JSON. Records written by an older build in plaintext are
still readable, so a rolling upgrade needs no flush.

Finishing a job is a single `SET`. It used to be `GET`/`SET`/`GET`/`SET` (an
`UpdateReport` followed by an `UpdateStatus`, each a read-modify-write), which
moved the whole report across the connection four times per completed scan.

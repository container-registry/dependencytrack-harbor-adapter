# Integrating dependencytrack-harbor-adapter with Harbor

This adapter implements the Harbor Pluggable Scanner Adapter API v1. It wraps the
[syft](https://github.com/anchore/syft) SBOM CLI and advertises exactly one
capability: **`sbom`**.

## READ THIS FIRST: this scanner has NO vulnerability capability

syft generates SBOMs. It does **not** detect vulnerabilities. This adapter therefore
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
- The adapter's own version is in `properties["org.label-schema.version"]`. The syft
  CLI version is reported in `scanner.version` (exec'd from `syft --version` at startup).

## Registering the scanner

Register it as an **additional, non-default** scanner (so it does not displace your
vulnerability scanner):

```sh
curl -sSf -X POST "https://<harbor-host>/api/v2.0/scanners" \
  -H "Content-Type: application/json" \
  -u "<admin-user>:<admin-pass>" \
  -d '{
    "name": "syft",
    "description": "syft SBOM generator (no vulnerability scanning)",
    "url": "http://dependencytrack-adapter:8080",
    "disabled": false,
    "use_internal_addr": true
  }'
```

Notes:

- `url` is the in-cluster / in-network address of the adapter. On the Harbor devenv this
  is the compose service name (e.g. `http://dependencytrack-adapter:8080`); in Kubernetes it is
  the Service DNS name.
- If the adapter is protected with `SCANNER_API_AUTH_API_KEY`, tell Harbor to
  authenticate **to the adapter** by registering with `"auth": "APIKey"` (the `-u`
  admin credentials on the curl above authenticate you to Harbor and are unrelated):

  ```json
  {
    "name": "syft",
    "url": "http://dependencytrack-adapter:8080",
    "auth": "APIKey",
    "access_credential": "<value of SCANNER_API_AUTH_API_KEY>"
  }
  ```

  With `auth: "APIKey"` Harbor sends every adapter request with the header
  `X-ScannerAdapter-API-Key: <access_credential>`
  (harbor `src/pkg/scan/rest/auth/auth.go`), which is exactly what the adapter's
  `requireAPIKey` middleware validates. Do not use `"auth": "Basic"`/`"Bearer"`
  here — those set an `Authorization` header the adapter does not read.
- Do **not** set this scanner as the project/system default if that would remove a
  vulnerability scanner from the default slot.

Bind it to a project (Harbor UI: Project -> Scanner -> select `syft`), or via the API.

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

syft pulls it, via `--image <ref> --image-src remote`. The adapter passes the
reference from the scan request, the transport flags below, and the Basic
credentials (anonymous when the authorization header is empty). Credentials go
through the environment as `WAYBILL_REGISTRY_<HOST>_USERNAME`/`_PASSWORD`, never
through argv.

**Plain-HTTP registries.** A `registry.url` with an `http://` scheme is treated as
insecure automatically and becomes `--insecure-registry <host:port>`. This is why
`use_internal_addr: true` works against the Harbor devenv's `http://core:8080`.

**Private-CA registries.** Set `SCANNER_SYFT_REGISTRY_CA_CERTS` to a
comma-separated list of PEM bundle paths mounted into the container; each becomes a
`--registry-ca-cert`. Every path is stat'd at startup, so a wrong path fails the
deployment rather than every scan. Example (K8s):

```yaml
env:
  - name: SCANNER_SYFT_REGISTRY_CA_CERTS
    value: /etc/syft/ca/harbor-ca.pem
volumeMounts:
  - name: registry-ca
    mountPath: /etc/syft/ca
    readOnly: true
```

`SCANNER_SYFT_INSECURE_TLS_SKIP_VERIFY=true` disables chain, hostname and expiry
verification for every pull. It logs a WARN at startup and is for dev/CI against
self-signed certs only — prefer the CA bundle in production.

Known registry-pull errors are classified from syft's stderr as
`RegistryPullAuth` (the registry rejected the credentials),
`RegistryPullTransport` (TLS or scheme mismatch — usually a missing
`--insecure-registry` or CA bundle), or `RegistryPull` (other registry
responses). The classification is heuristic — it matches syft's own m182
message strings — so a pull failure syft reports differently (network/DNS
errors, for example) can surface as `SyftExec`. Treat the first two as
configuration signals; do not assume every pull failure gets one of these
labels.

**Egress.** syft runs with `--offline`: it makes no outbound enrichment calls
(deps.dev, ClearlyDefined). See `docs/spike-m1.md` for why the flag, not the
`WAYBILL_OFFLINE` env var, is the real egress control. `--offline` does not affect
the registry pull.

**Disk.** syft writes its layer scratch and blob cache under the per-job work
dir (`SCANNER_SYFT_WORK_DIR`), which the adapter deletes when the job ends and
sweeps at startup. That directory is the bound on a scan's disk use, so give it a
sized mount: `emptyDir.sizeLimit` in K8s, `tmpfs: - /home/scanner:size=...` in
compose. Note disk is not the binding constraint — memory is; see "Memory sizing"
below, and `SCANNER_SYFT_MAX_IMAGE_SIZE`, which rejects an oversize artifact up
front rather than letting it fill the mount.

## Observing it

Scrape `GET /metrics`. The series and their meaning are in the README; the two
that answer most integration questions:

- `harbor_scanner_syft_scans_total{outcome="failure",category=...}` separates a
  broken scanner from a broken registration. A `category` of `RegistryPullAuth` or
  `RegistryPullTransport` is a problem with the scanner registration or the
  registry transport, not with syft.
- `harbor_scanner_syft_queue_wait_seconds` against
  `harbor_scanner_syft_scan_duration_seconds`. If the wait rather than the
  scan is what makes reports late, the worker pool is undersized: add replicas
  or raise `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY` (see the memory sizing rule
  below first), not the scan timeout.
- `harbor_scanner_syft_scans_total{category="Expired"}` above zero is the hard
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
| `node:22` | 400 MB | **2Gi** | **OOMKilled**, 500 | 1.57 GiB (ceiling) | 22s |
| `node:22` | 400 MB | 3Gi | 200, 1809 packages | 1.65 GiB | 55s |
| `node:22` | 400 MB | 4Gi | 200, 1809 packages | 1.75 GiB | 55s |
| `nvidia/cuda:12.6.3-devel` | 3.7 GB | **4Gi** | **OOMKilled**, 500 | 3.68 GiB (ceiling) | 16s |
| `nvidia/cuda:12.6.3-devel` | 3.7 GB | **7Gi** | **OOMKilled**, 500 | 6.94 GiB (ceiling) | 30s |

syft holds layer content in memory while pulling, so peak tracks image size at
**~4.7x** the compressed bytes (4.49x for golang, 4.68x for node at its highest observed peak) and is not
bounded by anything. The successful rows settle at a fixed peak whatever headroom
they are given; the killed rows consume every byte available, which puts the cuda
requirement above 7 GiB (~15 GiB by the ratio, untestable on a 7.7 GiB Docker VM).

Note `node:22` at 400 MB is an ordinary image, not a pathological one, and it
OOM-kills a 2Gi container. Size the limit from the ratio, not from intuition:

```
memory limit  >=  4.7  ×  SCANNER_SYFT_MAX_IMAGE_SIZE  ×  SCANNER_JOB_QUEUE_WORKER_CONCURRENCY   (plus headroom)
```

The shipped deployment pairs a **512 MiB** cap with a **4Gi** limit: 512 MiB ×
4.7 = 2.35 GiB peak, leaving 1.65 GiB spare. **Move the two together** — raising
the cap alone just moves the OOM back by one artifact, and raising the limit alone
wastes it.

1. **`SCANNER_JOB_QUEUE_WORKER_CONCURRENCY` stays at `1`.** Raising it multiplies
   the requirement. Scale with replicas, which spread memory across pods.
2. **The pre-pull size cap is what keeps an arbitrary image from OOM-killing the
   pod.** `SCANNER_SYFT_MAX_IMAGE_SIZE` (default 512 MiB, `0` disables)
   rejects an artifact whose compressed layers exceed it, before the pull
   allocates anything. Without it the kill lands on the container rather than on
   the one scan, so one oversized image takes every in-flight scan down with it.

   Verified on the devenv at a 2Gi limit: `nvidia/cuda:12.6.3-devel` (3.7 GB)
   returns HTTP 500 with `OOMKilled=false` and the container survives, while
   `golang:1.24` (316 MB) still scans normally.

   ```
   artifact core:8080/library/x@sha256:... is 3710564885 compressed bytes, over the
   536870912 limit; scanning it needs roughly 14842259540 bytes of memory
   (raise SCANNER_SYFT_MAX_IMAGE_SIZE and the container memory limit together)
   ```

   The check reads the manifest only, not blobs. For a multi-platform index it
   uses the largest single platform, since syft pulls one. A probe that
   cannot answer does **not** block the scan: it reaches the same registry over
   the same credentials as the pull, so making every scan depend on it would
   trade a rare OOM for a common outage. Those gaps are counted in
   `harbor_scanner_syft_image_probe_failures_total` — alert on it, because a
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

**Redis trust note.** Queued job payloads carry the full scan request, including
the per-scan Basic robot credential Harbor sends; they sit in Redis until a
worker takes them (harbor-scanner-trivy has the same property). Treat the
adapter's Redis as part of the credential trust boundary: keep it in-namespace
or AUTH-protected, do not share the instance with untrusted tenants, and prefer
short-lived per-scan robot accounts (Harbor's default) over long-lived ones.

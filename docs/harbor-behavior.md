# Observed Harbor behavior with the mikebom SBOM-only scanner

Recorded during the M7 devenv e2e (`test/devenv/run-e2e.sh`) against a live Harbor
`8gcr-main` devenv (core/jobservice/registryctl built from source, `SKIP_TRIVY`,
adapter joined to `harbor-0_default`). Every claim below is from a real API call or
core/jobservice log line captured during the run, not from documentation. Harbor
core version: the `8gcr-main` fork at the checked-out HEAD; adapter image
`mikebom-harbor-adapter` (mikebom `0.1.0-alpha.55`).

Fixtures (project `library`, repo `mikebom-e2e`):
- `:single` — the linux/amd64 child manifest of `alpine:3.20`
  (`sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e`,
  mediaType `application/vnd.oci.image.manifest.v1+json`), pushed by digest.
- `:index` — the full `alpine:3.20` multi-arch index
  (`sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`,
  mediaType `application/vnd.oci.image.index.v1+json`), 8 platform children.

## 1. Index artifact: Harbor fans the SBOM out to every child

Triggering `POST .../artifacts/<index-digest>/scan {"scan_type":"sbom"}` returns
`202` and Harbor then generates one SBOM **per child manifest**, not one for the
index:

- All 8 platform children ended with an `sbom.harbor` accessory and a valid SPDX
  2.3 document (16 packages each for alpine). Observed via
  `GET .../artifacts/<child>/accessories` and `.../artifacts/<sbom-digest>/additions/sbom`.
- The index artifact itself has **no** accessory:
  `GET .../artifacts/<index-digest>/accessories` returns `[]`.
- The adapter received one `POST /api/v1/scan` per child (8 separate scan jobs),
  each with `artifact.mime_type = application/vnd.oci.image.manifest.v1+json` and a
  distinct child digest.

Poll progression captured during the run (children accumulating SBOMs):

```
[01] index.scan_status=Running  children_with_sbom=0/8
[03] index.scan_status=Running  children_with_sbom=4/8
[06] index.scan_status=Running  children_with_sbom=8/8
```

`sbom_overview` on the index is **transient**: it reports `Running`/`Success` while
the child scans are in flight, then reads back `null` once complete
(`GET .../artifacts/<index-digest>?with_sbom_overview=true` → `sbom_overview: null`
after the fact, while the child accessories persist). The durable success signal for
an index is therefore the per-child `sbom.harbor` accessory, not the index-level
`sbom_overview.scan_status`. `run-e2e.sh` polls the children for this reason.

### Why (verified in the harbor source, read-only)

`src/controller/scan/base_controller.go:collectScanningArtifacts` walks the artifact
tree and calls `hasCapability(r, a)` (`src/controller/scan/checker.go:125-134`), which
tests the artifact's `ManifestMediaType` against the scanner's advertised
`consumes_mime_types`. The adapter advertises only
`application/vnd.docker.distribution.manifest.v2+json` and
`application/vnd.oci.image.manifest.v1+json` — the index media type
(`application/vnd.oci.image.index.v1+json`) is **not** in that list. So for an index:
`hasCapability` is false → `!supported && a.IsImageIndex()` → Harbor walks to the
children (`base_controller.go:211-214`); each child manifest **is** supported → added
to the scan set with `ErrSkip` (`:216-221`). Net effect: one scan job per child, none
for the index.

Implication for the adapter design: intentionally **not** advertising index media
types is correct. Harbor does the platform fan-out itself and hands the adapter only
concrete image manifests, so the adapter never has to resolve an index (it pulls the
single manifest digest Harbor sends and `crane.Save`s it to a tarball).

## 2. Vulnerability scan against this SBOM-only scanner

The adapter advertises exactly one capability (`type: sbom`); `support_vulnerability`
is **absent** (not `false`) in `GET /api/v2.0/scanners/{uuid}` (confirmed:
`.capabilities` → `{"support_sbom": true}` only).

### 2a. Explicit vulnerability trigger → HTTP 500

With the project bound to mikebom:

```
POST .../artifacts/<amd64-child>/scan  {"scan_type":"vulnerability"}   -> HTTP 500
POST .../artifacts/<amd64-child>/scan  {}   (default = vulnerability)   -> HTTP 500
```

Body: `{"errors":[{"code":"UNKNOWN","message":"internal server error"}]}`. Core logs:

```
[ERROR] /lib/http/error.go:58: {"errors":[{"code":"UNKNOWN",
  "message":"unknown: scan artifact library/mikebom-e2e@sha256:c64c687... failed"}]}
```

The bound scanner produces no vulnerability-report MIME type, so the vulnerability
scan handler cannot build a report placeholder and the request 500s. A caller must
not drive a vulnerability scan against this scanner.

### 2b. Auto-scan-on-push (`auto_scan` + `auto_sbom_generation`) → SBOM only, no vuln, push not blocked

Enabled both on `library` (`PUT /api/v2.0/projects/library` metadata
`auto_scan:"true"`, `auto_sbom_generation:"true"`) and pushed a fresh image. Result on
the pushed artifact:

```
{ "scan_overview": null,            # no vulnerability report produced
  "sbom_status": "Success",         # SBOM auto-generated
  "accessories": ["sbom.harbor"] }
```

The push succeeded and was not blocked. The event-triggered **vulnerability** auto-scan
produced nothing (no `scan_overview`); only the SBOM auto-generation ran. Harbor
swallows the "not scannable for this scan type" case for event-driven scans rather
than failing the push (`base_controller.go:264-268`: `if opts.FromEvent { return nil }`).

### 2c. Scan All (system, manual) → no vuln reports for sbom-bound artifacts, no global error

`POST /api/v2.0/system/scanAll/schedule {"schedule":{"type":"Manual"}}` → `201`. After
it ran, the mikebom-bound artifact still had `scan_overview: null` (no vulnerability
report) and its `sbom.harbor` accessory intact. Scan All issues **vulnerability**
scans; for artifacts whose project scanner is mikebom these produce no report and do
not error the Scan All run.

## Takeaways for deployment

- Register mikebom as an **additional, non-default** scanner and bind it per project
  (or run auto_sbom_generation), so the system default vulnerability scanner (Trivy on
  demo) still serves vulnerability scans. If mikebom becomes a project's scanner,
  every vulnerability path for that project degrades: explicit triggers 500, auto/Scan
  All silently produce no vulnerability data. This is the documented "sbom-only
  footgun".
- For index images, expect an accessory on each child, none on the index, and treat
  the per-child `sbom.harbor` accessory (not the index `sbom_overview`) as the
  success signal.

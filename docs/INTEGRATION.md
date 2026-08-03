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

## How the adapter pulls the artifact

The adapter pulls the image itself with go-containerregistry, using the Basic credentials
from the scan request (anonymous when empty), writes a docker-save tarball, and runs
waybill against the tarball (`--image <tarball>`). It does this because waybill's own OCI
client cannot pull from plain-HTTP or private-CA registries (plan D-1). `registry.url`
with an `http://` scheme is treated as insecure automatically, which is why
`use_internal_addr: true` works against the Harbor devenv's `http://core:8080`.

waybill runs with `--offline`: it never makes outbound enrichment calls (deps.dev,
ClearlyDefined). See `docs/spike-m1.md` for why the flag, not the `WAYBILL_OFFLINE` env
var, is the real egress control.

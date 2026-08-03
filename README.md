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

Harbor's OCI registry (in a devenv, and behind private CAs) cannot always be
reached by waybill directly: waybill hardcodes `https://` for OCI pulls and trusts
only webpki roots. Therefore the adapter pulls the artifact itself with
go-containerregistry (Basic creds decoded from the scan request, anonymous when
empty, plain-HTTP when `registry.url` is `http`), writes a docker-save tarball into
a per-job work dir, and runs:

```
waybill sbom scan --image <workdir>/image.tar --format spdx-2.3-json --output ...
```

waybill never touches the network for the artifact pull. Enrichment network calls
are disabled with the `--offline` CLI flag (see `docs/spike-m1.md`).

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

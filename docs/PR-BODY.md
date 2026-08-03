# feat: waybill Harbor scanner adapter (SBOM-only)

A Harbor Pluggable Scanner Adapter (Scanner Adapter API v1) that wraps the
[waybill](https://github.com/kusari-oss/waybill) Rust SBOM CLI so Harbor can generate SPDX
SBOM accessories. It advertises exactly one capability, `type: sbom`, as a **complement to**
a vulnerability scanner such as Trivy. Harbor core performs the accessory push; the adapter
only serves the API.

Go module `github.com/container-registry/waybill-harbor-adapter`, binary `scanner-waybill`,
architecture ported from `harbor-scanner-trivy` (gorilla/mux, caarlos0/env, slog,
prometheus, Redis store + queue).

## Update: upstream renamed, and the D-1 workaround is gone

Two things changed since this PR was opened.

**1. `kusari-oss/mikebom` is now `kusari-oss/waybill`.** Crates are
`waybill-cli`/`waybill-common`, the binary is `waybill`, and release assets are named
`waybill-*` from `v0.1.0-alpha.66` (`mikebom-*` up to `alpha.65`). This PR renames the
adapter to match throughout: module path, binary, package, image name, and the
`SCANNER_MIKEBOM_*` → `SCANNER_WAYBILL_*` env prefix.

> ⚠️ The GitHub repository still has its old name. Renaming
> `container-registry/mikebom-harbor-adapter` → `waybill-harbor-adapter` is an
> owner action and is a prerequisite for the module path to resolve (`go install`,
> `go get`). Nothing else depends on it: builds, CI and the image are unaffected,
> since the module is only ever built from this tree.

**2. waybill can now pull from Harbor itself, so the adapter stopped doing it.** The
original design (D-1) had the adapter pull the artifact with go-containerregistry and hand
waybill a docker-save tarball, because waybill's OCI client hardcoded `https://` and trusted
only webpki roots. waybill **milestone 182** closed both:

```
--insecure-registry <host[:port]>   plain-HTTP registries
--registry-ca-cert <path>           private/corporate CA bundles
--insecure-tls-skip-verify          dev/CI escape hatch
```

so the adapter now runs `waybill sbom scan --image <ref> --image-src remote` and waybill
performs the pull. `docs/upstream-issues.md` tracks all three upstream issues: **1 and 2 are
resolved**, 3 (caller-supplied Bearer token) is still open, which is why Bearer
authorization is still rejected with 422.

The actual argv, taken from a live devenv scan:

```
waybill --offline --timeout 300 sbom scan
  --image core:8080/library/waybill-e2e@sha256:c64c687c…
  --image-src remote
  --format spdx-2.3-json --output spdx-2.3-json=/home/scanner/work/scan-2118728078/report.spdx.json
  --output openvex=/home/scanner/work/scan-2118728078/out.vex.json
  --insecure-registry core:8080
  --no-oci-cache
```

What this buys:

- **One copy of the image instead of two.** The docker-save tarball is gone; waybill streams
  layers into the per-job workdir it already uses as `HOME`/`TMPDIR`.
- **go-containerregistry off the runtime path** (test-only now), and with it a chunk of the
  adapter's own pull, auth and error-handling surface.
- **Private-CA support the adapter never had.** Even under D-1 the adapter's own crane pull
  had no custom-CA option; `SCANNER_WAYBILL_REGISTRY_CA_CERTS` now covers it, with every
  path stat'd at startup so a bad mount fails the deployment, not every scan.
- `--image-src remote` is pinned, never defaulted: waybill's default order is
  `docker,podman,remote`, and the image ships no container runtime to probe.

Costs, stated plainly: the pull now happens inside a subprocess, so its failures arrive as
stderr rather than as typed Go errors. They are classified back out into
`RegistryPullAuth` / `RegistryPullTransport` / `RegistryPull` against waybill's own m182
message strings, so a misconfigured scanner registration stays distinguishable from a broken
scanner in Harbor's UI. Credentials move to the environment
(`WAYBILL_REGISTRY_<HOST>_USERNAME`/`_PASSWORD`) and never appear in argv, which is readable
by anything that can stat `/proc/<pid>/cmdline`.

### Verification of the upstream fix

Against waybill `0.1.0-alpha.69` and a local `registry:2` — plain HTTP with htpasswd on
`:5555`, TLS behind a self-signed private CA on `:5556`:

| Case | Flags | Result |
|------|-------|--------|
| plain HTTP, no flag | — | `TLS handshake failed … pass --insecure-registry localhost:5555` |
| plain HTTP, no creds | `--insecure-registry` | `registry returned 401 with Basic auth challenge … no credentials are configured` |
| plain HTTP + creds | `--insecure-registry` + `WAYBILL_REGISTRY_*` | exit 0, SPDX with 17 packages |
| private CA, no flag | — | `TLS certificate chain validation failed … pass --registry-ca-cert <path>` |
| private CA | `--registry-ca-cert ca.crt` | exit 0, SPDX written |
| private CA | `--insecure-tls-skip-verify` | exit 0, SPDX written |
| bad CA path | `--registry-ca-cert /nonexistent.pem` | exit 1 before any network call, names the path |

Credential env keys include the port: `WAYBILL_REGISTRY_LOCALHOST_5555_USERNAME` resolves,
`WAYBILL_REGISTRY_LOCALHOST_USERNAME` does not. `pkg/waybill.registryEnvKey` mirrors that
derivation and is unit-tested against it.

## SBOM-only warning (read before registering)

**This scanner has NO vulnerability capability.** waybill generates SBOMs; it does not
detect CVEs. The adapter advertises only `sbom` and rejects vulnerability scan requests with
HTTP 422. Verified downstream behavior in Harbor (`docs/harbor-behavior.md`): if this becomes
a project's scanner, explicit vulnerability triggers return HTTP 500, and auto-scan / Scan
All silently produce no vulnerability data. **Register it as an additional, non-default,
project-bound scanner alongside a real vulnerability scanner. It complements, it does not
replace.**

## Acceptance status

**M7 (devenv e2e) now passes.** Its acceptance was previously halted on exactly the upstream
blockers this PR closes. Run against a live Harbor devenv on slot 0:

```
=== Fixture :single (single manifest) ===
trigger HTTP 202 → Pending → Running → Success
{"spdxVersion":"SPDX-2.3","packages":16}  + sbom.harbor accessory

=== Fixture :index (multi-arch index, 8 platform children) ===
children_with_sbom=0/8 → 1/8 → 4/8 → 8/8
index itself carries no accessory (fan-out target is the children) ✓
all 8 children: sbom.harbor accessory + valid SPDX 2.3 ✓

=== GATE PASSED ===
```

Component tier (`task test:component`, real image, `registry:2` over plain HTTP with
htpasswd, read-only rootfs as uid 65532): 5/5 pass. Unit tests, `go vet` and
`task lint:local` are clean.

Note: `task test` must run with the local command sandbox disabled — httptest port binds are
refused by the sandbox (`bind: operation not permitted`). That is a sandbox denial, not a
test failure; CI is unaffected.

## Review findings addressed

Everything raised by CodeRabbit, cubic, Copilot and zizmor on this PR has been triaged.

**Queue durability** (cubic, two findings — the most substantive). Redis Pub/Sub loses
accepted jobs two ways: `Publish` succeeds with zero subscribers, so anything enqueued
during a worker restart vanishes; and go-redis's `PubSub.Channel()` buffers 100 messages and
drops the rest while the reader loop is busy scanning. Either way the store record stays
`Queued` and Harbor 302-polls a job no worker will ever run, until the TTL. Moved to a Redis
list (`RPUSH`/`BRPOP`): the entry persists and goes to exactly one consumer whenever one
shows up. Two miniredis-backed regression tests pin both failure modes — enqueue before any
worker starts, and a 150-job backlog against the old 100-message buffer.

**Bounded API shutdown** (cubic). `http.Server.Shutdown` got `context.Background()`, so one
stalled connection could hold it open indefinitely — and the signal handler runs it before
`worker.Stop()` and `rdb.Close()`, so neither ran either. Now capped at 10s.

**`SetXX` result checked** (cubic). The store's update path only checked `Err()`, so a key
that expired between the `Get` and the write reported success while dropping the update.

**Config validation** (cubic). `SCANNER_STORE_BACKEND` is normalized and validated against
the known set, so a typo or `"Memory"` can no longer take the Redis path while skipping the
checker's fail-fast ping. Empty Redis namespaces and a non-positive `ScanJobTTL` are
rejected too, as is `SCANNER_WAYBILL_TIMEOUT<=0` (previously a listed open finding).

**apply-settings** (cubic + zizmor). `applyAll` swallowed every API error, so a deliberate
apply run went green having changed nothing; failures are now collected and fail the step.
Checkout no longer persists credentials, and `js-yaml` is pinned rather than floating — this
job holds a token that can rewrite repository settings.

**`run-e2e.sh`** (cubic). Dropped `curl -f` from `trigger_scan`: under `set -e` a non-2xx
aborted the assignment and killed the script before the status check and `fail()`'s
diagnostic dump, exactly when they were needed.

**Docs** (cubic). `cosign verify` pins the expected workflow identity and issuer instead of
wildcard regexes, which proved only that *some* Fulcio-backed signature existed. SOPS uses
`SOPS_AGE_KEY_FILE` rather than an inline key in shell history.

**Stale `ci.yml` comment** removed (CodeRabbit).

The Copilot findings (`makeIdentifier` returning an empty ID, redisx pool timeouts, the gzip
level comment, the apply-settings schedule mode, the stray `</content>`) were already fixed
in `ceac2d3`; re-verified against the current tree.

**Image-size cap / workdir bounds** (cubic P1) is **partially addressed and partially
carried**. The adapter no longer performs an unbounded `crane.Pull` + `crane.Save`, and the
tarball copy is gone. There is still no pre-pull size cap: an oversize image is bounded by
the per-job workdir mount, not rejected up front. That mount is sized in every shipped
harness (`size=2G`/`4G` on compose tmpfs) and `docs/INTEGRATION.md` now states the
`emptyDir.sizeLimit` requirement for K8s explicitly. A real pre-pull cap needs a
manifest-size probe before handing the reference to waybill; tracked, not done.

## What is NOT included

- **No release** (M8). release-please owns tags; the first `feat:` merge proposes v0.1.0.
- **No deploy** (M9) to demo.goharbor.io and **no scanner registration/smoke** (M10). A
  ready-to-paste `extraManifests` block and the owner command sequence are in
  `docs/HANDOFF.md`.
- **No FedIDP robot.** Nothing publishes to `8gcr` until the federated robot exists on
  `8gears.container-registry.com` (global GitHub OIDC provider, claim rule
  `repository == container-registry/waybill-harbor-adapter`, audience
  `https://8gears.container-registry.com`, push on `8gcr`). See `docs/HANDOFF.md` §c.
- **No image published**, and **the GitHub repo rename is not done** (owner action).

## Open findings (carried, not fixed)

Full list in `docs/HANDOFF.md` §e. Fixed in this PR: queue durability, Redis pool timeouts,
`SCANNER_WAYBILL_TIMEOUT<=0`. Still open:

- No pre-pull image-size cap; the per-job workdir mount is the only bound (see above).
- No pull-phase deadline separate from the job deadline. It is now less sharp than it was —
  the pull and the scan share waybill's `--timeout` plus the job deadline — but one stalled
  pull still occupies a worker for the full budget at concurrency 1.
- Report finish path moves the multi-MB SBOM across Redis ~4x and stores it uncompressed;
  collapse to one write and gzip.
- Throughput mismatch: serial adapter vs parallel Harbor jobservice; document sizing / skip
  jobs past Harbor's 30-min budget.
- Minor: process-group kill on backstop; CI cost (lint tools compiled from source, needless
  QEMU in publish-image).

## Reviewer checklist

- [ ] Dropping D-1 for waybill's native remote pull is the right call now that m182 exists;
      the stderr-based pull-error classification is an acceptable trade for losing typed
      pull errors.
- [ ] Credentials via `WAYBILL_REGISTRY_*` env (never argv) is sound, and setting both the
      per-registry and generic pair is justified — one subprocess pulls one image from one
      registry.
- [ ] The SSRF surface of `/scan` accepting arbitrary registry URLs is acceptable behind
      API-key auth + NetworkPolicy for the demo.
- [ ] The Redis list queue is the right durability floor for v1, and the remaining
      at-least-once gap (a worker crashing mid-scan loses the job until TTL) is acceptable.
- [ ] Contract tests genuinely pin the exact D-3 MIME strings and pass Harbor's vendored
      `Validate()` / `RawSBOMReport` round-trip.
- [ ] The sbom-only footgun is adequately guarded (422 on vuln requests) and documented;
      registration guidance (non-default, project-bound) is clear.
- [ ] `--offline` is passed in argv (not relying on `WAYBILL_OFFLINE` env) so no enrichment
      egress occurs, and it is understood that `--offline` does not gate the registry pull.
- [ ] The waybill pin (`versions.env`) is at or above `v0.1.0-alpha.69` — below m182 every
      plain-HTTP and private-CA deployment breaks.
- [ ] Apache-2.0 redistribution obligations (LICENSE in image, NOTICE) are correct.
- [ ] release-please config: manifest seeded `0.0.0`, `include-v-in-tag`,
      `bump-minor-pre-major`, squash-merge only; `exclude-paths` covers `.github`/`docs`.
- [ ] The GitHub repository rename to `waybill-harbor-adapter` is scheduled before anyone
      needs the module path to resolve.

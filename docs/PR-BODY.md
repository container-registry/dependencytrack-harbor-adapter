# feat: waybill Harbor scanner adapter (SBOM-only)

**Open this as a DRAFT.** Milestones M1–M5 are complete and accepted; M7 (devenv e2e) is
committed but its acceptance is halted on blockers that live in sibling repos, not in this
one (details under "Acceptance status" below). This repo's own tree is clean and both gates
(`task build`, `task test`) are green.

## What this adds and why

A Harbor Pluggable Scanner Adapter (Scanner Adapter API v1) that wraps the
[waybill](https://github.com/kusari-oss/waybill) Rust SBOM CLI so Harbor can generate SPDX
SBOM accessories. It advertises exactly one capability, `type: sbom`, as a **complement to**
a vulnerability scanner such as Trivy. Harbor core performs the accessory push; the adapter
only serves the API.

Go module `github.com/container-registry/waybill-harbor-adapter`, binary `scanner-waybill`,
architecture ported from `harbor-scanner-trivy` (gorilla/mux, caarlos0/env, slog,
prometheus, Redis store + queue).

## The core design decision (D-1) and the two waybill constraints that forced it

Two facts, both verified against the waybill source, shaped the architecture:

1. **waybill cannot pull from plain-HTTP or private-CA registries.** Its OCI client
   hardcodes `https://` (`waybill-cli/src/scan_fs/oci_pull/registry.rs:455,464`) and trusts
   only **webpki roots** — no custom CA, no Bearer, no insecure registry. The Harbor devenv
   emits `registry.url = http://core:8080`, so waybill's own remote pull is unusable there.
2. **waybill accepts a docker-save tarball as `--image` input** (its CLI reference).

**D-1 — the adapter pulls the artifact itself.** It uses go-containerregistry with the Basic
credentials decoded from the scan request (anonymous when empty, plain-HTTP when
`registry.url` is `http://`), writes a docker-save tarball into a per-job workdir, and runs
`waybill sbom scan --image <workdir>/image.tar --format spdx-2.3-json --output ...`.
**waybill never touches the network** (`--offline` in argv is the actual egress control;
the `WAYBILL_OFFLINE` env var alone does not disable enrichment calls — see
`docs/spike-m1.md`). Remote pull (`--image-src remote`) is a v2 optimization gated on three
upstream waybill issues we filed (insecure-registry, custom CA, Bearer;
`docs/upstream-issues.md`).

## SBOM-only warning (read before registering)

**This scanner has NO vulnerability capability.** waybill generates SBOMs; it does not
detect CVEs. The adapter advertises only `sbom` and rejects vulnerability scan requests with
HTTP 422. Verified downstream behavior in Harbor (`docs/harbor-behavior.md`): if this becomes
a project's scanner, explicit vulnerability triggers return HTTP 500, and auto-scan / Scan
All silently produce no vulnerability data. **Register it as an additional, non-default,
project-bound scanner alongside a real vulnerability scanner. It complements, it does not
replace.**

## Milestone-by-milestone summary with gate evidence

| Milestone | Commit | Gate | Evidence |
|---|---|---|---|
| M1 Decision spike + upstream filing | `905a495` | valid SPDX from a tarball; pin recorded | SPDX 2.3 produced; waybill pinned `v0.1.0-alpha.55` @ `sha256:806521f…8ae2746`; SBOM sizes measured (golang:1.23 = 5,507,501 raw / 1,054,388 gzip, 5.2x); 3 upstream issues filed |
| M2 Repo scaffold + build tooling | `9d78a0b` | `task build/test/lint:local/image:local` green; container runs uid 65532, read-only rootfs, `waybill --version` execs | scaffold, Taskfile, Dockerfile (distroless nonroot), versions.env, compose, settings bundle |
| M3 Adapter implementation | `d13ea47` | `task test` green incl. contract tests | full service (config/checker/store/queue/pull/wrapper/controller/HTTP); contract golden tests pin D-3 MIME strings + `RawSBOMReport` round-trip against vendored Harbor `Validate()` |
| M4 Component tier | `49a8985` | `task test:component` green against the real image | compose `registry:2` (htpasswd) + real adapter image; POST→302+Refresh-After→200 loop, failure path, read-only-rootfs assertion, gzip/size measurement, VEX fixture |
| M5 CI + release plumbing | `bbfd0ba` | workflows lint clean | ci/hygiene/pr-title/publish-image(WIF)/main-image/release-please; release-please config + manifest `0.0.0`; `docs/RELEASES.md`, `docs/INTEGRATION.md` |
| M7 Devenv e2e | `3cae269` | accessory + success for both fixtures | committed; acceptance halted (see below). SBOMs genuinely produced: 8/8 index children + single fixture carry `sbom.harbor` + valid SPDX 2.3 |

Final gate run on branch HEAD `3cae269`: `task build` produces the static linux binary;
`task test` (`-short -race`) passes all packages (contract 100% of the D-3 MIME strings;
coverage e.g. registry 92.3%, waybill 88.1%, memory store 94.3%). `task test` must run with
the local command sandbox disabled — httptest port binds are refused by the sandbox
(`bind: operation not permitted`), which is a sandbox denial, not a test failure; CI is
unaffected.

## Acceptance status (why draft)

M7's gate requires `git -C ../harbor status --porcelain` to be empty. It is not: `../harbor`
carries an unrelated `versions.env` delve bump and a temporary goharbor PR #23375 repro test
(`grep -l waybill` finds nothing in either), and `../dedicated-container-registry` has three
unrelated modified tenant files. Neither is output of this work; both are the owner's to
revert. Additionally the M7 index success signal is the per-child `sbom.harbor` accessory,
not the transient index `sbom_overview.scan_status` (source-justified in
`docs/harbor-behavior.md`), and `test/devenv/run-e2e.sh` has a known re-runnability defect
(asserts the lazily-cached `support_sbom` once). Full detail and owner commands in
`docs/HANDOFF.md`.

## What is NOT included

- **No release** (M8). release-please owns tags; the first `feat:` merge proposes v0.1.0.
- **No deploy** (M9) to demo.goharbor.io and **no scanner registration/smoke** (M10). A
  ready-to-paste `extraManifests` block and the owner command sequence are in
  `docs/HANDOFF.md`.
- **No FedIDP robot.** Nothing publishes to `8gcr` until the federated robot exists on
  `8gears.container-registry.com` (global GitHub OIDC provider, claim rule
  `repository == container-registry/waybill-harbor-adapter`, audience
  `https://8gears.container-registry.com`, push on `8gcr`). See `docs/HANDOFF.md` §c.
- **No image published** and **no GitHub repo/remote created** by this work.

## Open performance findings (carried, not fixed)

Known and deferred; none block a draft, several matter before scaling past the single-replica
demo. Full list in `docs/HANDOFF.md` §e.

- Queue is Redis Pub/Sub: silent job loss under backlog (>~101 msgs) and on restart. Move to
  a Redis list/stream for durable at-least-once delivery.
- Per-job workdir unbounded and RAM-backed (tmpfs) in the shipped compose harnesses; no
  image-size cap before pull (SSRF surface). Use disk-backed emptyDir with sizeLimit in K8s,
  add `size=` to compose tmpfs, reject oversize images.
- No pull-phase deadline separate from the job deadline; one stalled pull halts all scanning
  at concurrency 1.
- Report finish path moves the multi-MB SBOM across Redis ~4x and stores it uncompressed;
  collapse to one write and gzip.
- Throughput mismatch: serial adapter vs parallel Harbor jobservice; document sizing / skip
  jobs past Harbor's 30-min budget.
- Minor: clamp `Refresh-After` ≤127 (Harbor parses int8); reject `SCANNER_WAYBILL_TIMEOUT<=0`;
  wire Redis pool timeouts for the `redis://` scheme; process-group kill on backstop; CI cost
  (lint tools compiled from source, needless QEMU in publish-image).

## Reviewer checklist

- [ ] D-1 is the right call given waybill's https-only + webpki-only constraints; the
      SSRF surface of `/scan` accepting arbitrary registry URLs is acceptable behind API-key
      auth + NetworkPolicy for the demo.
- [ ] Contract tests genuinely pin the exact D-3 MIME strings and pass Harbor's vendored
      `Validate()` / `RawSBOMReport` round-trip.
- [ ] The sbom-only footgun is adequately guarded (422 on vuln requests) and documented;
      registration guidance (non-default, project-bound) is clear.
- [ ] `--offline` is passed in argv (not relying on `WAYBILL_OFFLINE` env) so no enrichment
      egress occurs.
- [ ] Redis namespaces are set explicitly in every deployment artifact; single replica in v1.
- [ ] The waybill pin (`versions.env`: tag + digest) and Apache-2.0 redistribution
      obligations (LICENSE in image, NOTICE) are correct.
- [ ] release-please config: manifest seeded `0.0.0`, `include-v-in-tag`,
      `bump-minor-pre-major`, squash-merge only; `exclude-paths` covers `.github`/`docs`.
- [ ] Accept the documented M7 deviations (per-child accessory as the index success signal;
      the sibling-repo cleanliness blockers are owner-side) before un-drafting.
- [ ] Open performance findings are acceptable to defer for a demo rollout; queue durability
      and workdir bounding are tracked for the production follow-up.

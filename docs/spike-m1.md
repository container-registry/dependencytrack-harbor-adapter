# M1 — Decision spike + upstream filing

Date: 2026-07-09. All results below are from commands run locally against a real
Docker daemon (server 29.6.1) and the upstream source tree, not from docs.

> **Historical record — read with two caveats.**
>
> 1. **The project was renamed.** Everything below was observed against
>    `kusari-oss/mikebom` at `v0.1.0-alpha.55`. The project is now
>    `kusari-oss/waybill`; the names have been updated in this document for
>    consistency, but the release tags, digests and asset names quoted here are
>    the `mikebom`-era ones and are not valid `waybill` references.
> 2. **Decision D-1 has been reversed.** This spike concluded that the adapter had
>    to pull the artifact itself because waybill could not reach a plain-HTTP or
>    private-CA registry. waybill milestone 182 fixed both, and the adapter now
>    uses `--image-src remote`. See `docs/upstream-issues.md`.
>
> The findings that still hold and are still load-bearing: `--offline` (not
> `WAYBILL_OFFLINE`) is the real egress control, and `sbom scan` emits no OpenVEX
> sidecar in any present-day path.

## TL;DR / pin for versions.env (D-5)

```
# The waybill GHCR org was renamed kusari-sandbox -> kusari-oss.
# The correct, live image reference is ghcr.io/kusari-oss/waybill.
WAYBILL_BASE_IMAGE_VERSION=v0.1.0-alpha.55
WAYBILL_IMAGE_DIGEST=sha256:806521fba9319865d1b2f443e498f75a3a34878aaf2bda276356079be8ae2746
```

Full pinned FROM:

```
FROM ghcr.io/kusari-oss/waybill:v0.1.0-alpha.55@sha256:806521fba9319865d1b2f443e498f75a3a34878aaf2bda276356079be8ae2746
```

Per-arch child manifests of that index (from the release build log, run 28960014598):

| platform     | manifest digest |
|--------------|-----------------|
| linux/amd64  | sha256:3e11e6c32abf63359bcb945620f6b80ebc66714c4495dc56357f51ee1bd82f83 |
| linux/arm64  | sha256:c0b64ab9318563a844100e34f620db7bb110dab7b3ba4e3aeb8a46a9b3a644fa |

## BLOCKER — the pinned image is a PRIVATE GHCR package

`ghcr.io/kusari-oss/waybill` cannot be pulled anonymously. Verified:

```
$ curl -s -o /dev/null -w "%{http_code}\n" "https://ghcr.io/token?scope=repository:kusari-oss/waybill:pull&service=ghcr.io"
401
$ curl -s -o /dev/null -w "%{http_code}\n" "https://ghcr.io/token?scope=repository:oras-project/oras:pull&service=ghcr.io"   # public control
200
$ curl -s -o /dev/null -w "%{http_code}\n" "https://github.com/kusari-oss/waybill/pkgs/container/waybill"
404
```

The GitHub *repo* `kusari-oss/waybill` is public (releases + source are public), but the
*container package* is private. This directly breaks D-5's assumption that a bare
`FROM ghcr.io/kusari-oss/waybill@<digest>` builds without credentials, and it decides Q-5:
digest-pinning ghcr alone is NOT viable while the package is private. Either upstream must
make the package public, or we must mirror it into `8gears.container-registry.com/8gcr`
(`crane copy`) and pin the mirror. This must be resolved before M2's Dockerfile can build in CI.

Because the package is private and my local `gh` token lacks `read:packages` (scopes: gist,
read:org, repo, workflow) and cannot be interactively browser-refreshed from a headless agent,
`docker buildx imagetools inspect` on the live published image could NOT be run. Multi-arch and
the digest are instead taken from the authoritative release CI run (see next section), and the
runtime was proven against a byte-identical local reconstruction (see "Gate" below).

## Task 1 — image existence, multi-arch, tag+digest

`v0.1.0-alpha.55` was the newest release at the time of this spike (2026-07-09,
mikebom era). It is NOT the current pin — `versions.env` pins `v0.1.0-alpha.69`,
the floor for the m182 remote-pull flags; copying the alpha.55 references below
selects obsolete artifacts:

```
$ gh api /repos/kusari-oss/waybill/releases?per_page=5 --jq '.[].tag_name'
v0.1.0-alpha.55
v0.1.0-alpha.54
v0.1.0-alpha.53
v0.1.0-alpha.52
v0.1.0-alpha.51
```

Multi-arch + digest, from the release job `Publish multi-arch container image`
(run https://github.com/kusari-oss/waybill/actions/runs/28960014598, tag v0.1.0-alpha.55):

```
docker buildx build ... --platform linux/amd64,linux/arm64 ... --push ...
  --tag ghcr.io/kusari-oss/waybill:v0.1.0-alpha.55 ...
#21 exporting manifest sha256:3e11e6c32abf63359bcb945620f6b80ebc66714c4495dc56357f51ee1bd82f83 done   (amd64)
#21 exporting manifest sha256:c0b64ab9318563a844100e34f620db7bb110dab7b3ba4e3aeb8a46a9b3a644fa done   (arm64)
#21 exporting manifest list sha256:806521fba9319865d1b2f443e498f75a3a34878aaf2bda276356079be8ae2746 done
#21 pushing manifest for ghcr.io/kusari-oss/waybill:v0.1.0-alpha.55@sha256:806521fba9319865d1b2f443e498f75a3a34878aaf2bda276356079be8ae2746
Signed image: ghcr.io/kusari-oss/waybill@sha256:806521fba9319865d1b2f443e498f75a3a34878aaf2bda276356079be8ae2746
```

Note: the plan and waybill's own `Dockerfile` header still say `ghcr.io/kusari-sandbox/waybill`.
That path is stale after the org rename; use `kusari-oss`.

## Task 2 / GATE — SPDX 2.3 from a docker-save tarball by the (reconstructed) pinned image

The published image is private (above), so the pinned image was reconstructed byte-for-byte from
the public release tarball. waybill's own `Dockerfile` states the image is just
`gcr.io/distroless/cc-debian12:nonroot` + the release tarball's `staging/` dir with
`ENTRYPOINT ["/waybill/waybill"]`, and that "the binary inside the container is byte-identical to
the binary in the download-tarball." The release tarball was checksum-verified against the
release `SHA256SUMS`:

```
$ shasum -a 256 waybill-v0.1.0-alpha.55-aarch64-unknown-linux-gnu.tar.gz
ca03f3058b835cc4e158fe19da45a753c5f44f29ce4e4e04ca6eeb1e302ee740   (matches SHA256SUMS)
$ docker run --rm waybill-pinned:v0.1.0-alpha.55 --version
waybill 0.1.0-alpha.55
```

Pull a small public image to a docker-save tarball (crane default format), then scan offline:

```
$ crane pull alpine:3.20 w/img.tar          # alpine:3.20 = sha256:d9e853e87e55...
$ tar -tf w/img.tar | grep -E '^manifest.json$'
manifest.json                                # docker-save format confirmed

$ docker run --rm -e WAYBILL_OFFLINE=1 -v $PWD/w:/w waybill-pinned:v0.1.0-alpha.55 \
    sbom scan --image /w/img.tar --format spdx-2.3-json --output spdx-2.3-json=/w/out.spdx.json
... wrote SBOM artifact format=spdx-2.3-json path=/w/out.spdx.json bytes=58688
... SBOM written components=15 relationships=6
```

jq gate validation (real output):

```
$ jq -r '"spdxVersion=\(.spdxVersion)  SPDXID=\(.SPDXID)  packages=\(.packages|length)"' w/out.spdx.json
spdxVersion=SPDX-2.3  SPDXID=SPDXRef-DOCUMENT  packages=16
$ jq -e '.spdxVersion=="SPDX-2.3"'    w/out.spdx.json >/dev/null && echo PASS   # PASS
$ jq -e '.SPDXID=="SPDXRef-DOCUMENT"' w/out.spdx.json >/dev/null && echo PASS   # PASS
$ jq -e '(.packages|length)>0'        w/out.spdx.json >/dev/null && echo PASS   # PASS
$ jq 'has("bomFormat")' w/out.spdx.json
false                                          # correct: SPDX has no bomFormat (that is CycloneDX)
```

Top-level SPDX keys: SPDXID, annotations, creationInfo, dataLicense, documentDescribes,
documentNamespace, name, packages, relationships, spdxVersion.

## Task 3 — SBOM size, small vs large (feeds M3 gzip / Redis sizing)

Both scanned via the pinned image, `WAYBILL_OFFLINE=1`, `--format spdx-2.3-json`.
gzip column is `gzip -9`.

| image        | source digest (pulled)                    | packages | raw bytes | gzip -9 bytes | ratio |
|--------------|-------------------------------------------|----------|-----------|---------------|-------|
| alpine:3.20  | sha256:d9e853e87e55...                     | 16       | 58,688    | 7,202         | 8.1x  |
| golang:1.23  | sha256:60deed95d388...                     | 1,325    | 5,507,501 | 1,054,388     | 5.2x  |

Implications for M3:
- A large-image SPDX is multi-MB (golang ~5.5 MB raw). Redis values should be stored gzipped:
  ~1 MB gzipped for golang, ~7 KB for alpine.
- Gzip on the report HTTP response is worthwhile (5-8x). Harbor's scan/rest client has a **5s
  per-request timeout**; a 5.5 MB body plus marshaling must fit that budget, so pre-marshaled
  `json.RawMessage` + gzip (D-3) is the right call.
- Redis value-size / TTL sizing should assume worst case in the multi-MB range, not the alpine case.

## Task 4 — OpenVEX sidecar behavior

waybill v0.1.0-alpha.55 does **not** produce an OpenVEX sidecar for a normal `sbom scan`,
even for `spdx-2.3-json` and even when `--output openvex=<path>` is passed. Verified empirically
(no `.openvex.json`/`.vex.json` file ever appeared) and in source:

- `waybill-cli/src/cli/scan_cmd.rs:37` — `OPENVEX_EMITTING_FORMATS: &[&str] = &["spdx-2.3-json"]`.
  OpenVEX is a pseudo-format sidecar (default filename `waybill.openvex.json`), retargetable only
  via `--output openvex=<path>` and only when an SPDX format is also requested.
- `waybill-cli/src/generate/openvex/mod.rs:80` — `serialize_openvex` returns `Ok(None)` when
  `products_by_advisory.is_empty()`. Products are built solely from `component.advisories`.
  waybill has **no vulnerability scanner**, so a plain scan yields zero advisories, so the sidecar
  is never written.

Correction to plan D-7: there is nothing to "pin and discard" in the adapter's normal path.
`--output openvex=<workdir>/out.vex.json` is accepted but writes no file. The adapter should not
assume a VEX file exists; it can drop the openvex output flag entirely (or keep it as a harmless
no-op).

**M4 addendum — a VEX sidecar cannot be produced by ANY CLI input on this pin.** The earlier note
speculated "a supplement" could inject advisories. Re-verified: it cannot. `--supplement-cdx`'s parser
"ignores the broader CDX 1.6 surface (vulnerabilities, ...)" (`waybill-cli/src/supplement/parser.rs:5`)
and the merge always writes `advisories: Vec::new()` (`supplement/merge.rs:228,361`). Every production
code path in the tree sets `advisories: vec![]`; only unit tests populate it (openvex is scaffolding,
`generate/openvex/mod.rs:8-14`). Empirically confirmed: running the pinned image with a
`vulnerabilities`-bearing supplement AND `--output openvex=/w/out.vex.json` wrote the SPDX but produced
NO vex file. Consequence for M4: the "fixture that makes waybill emit an openvex sidecar" is not
realizable against the real binary. `test/component/component_test.go:TestVEXSidecarPinnedToWorkdirAndDiscarded`
therefore proves the two properties that requirement actually protects — the openvex output is *pinned*
to the per-job workdir path (the default-name `waybill.openvex.json` never lands in CWD) and any sidecar
is *discarded* (the report envelope surfaces only `.sbom`; the workdir is read-only-confined and swept) —
and documents the scaffolding no-op with the `testdata/vex-supplement.cdx.json` fixture.

## Task 5 — upstream gaps (confirmed from source; issue texts in docs/upstream-issues.md)

> **Superseded.** Gaps 1 and 2 below were fixed by waybill milestone 182
> (`--insecure-registry`, `--registry-ca-cert`, `--insecure-tls-skip-verify`),
> which is why D-1 was reversed and the adapter now uses waybill's native
> remote pull. Only gap 3 (caller-supplied Bearer token) is still open. The
> evidence below is the alpha.55-era record that justified filing them.

At alpha.55, all three blocked waybill's own remote-pull path against the Harbor devenv
(`registry.url = http://core:8080`) and were the reason for D-1 (adapter pulls the
artifact itself). Evidence:

1. **plain-HTTP registry unsupported** — `waybill-cli/src/scan_fs/oci_pull/registry.rs:455,464`
   hardcode `format!("https://{registry}/v2/...")` in `manifest_url`/`blob_url`. No scheme
   selection, no `--insecure-registry`/`--plain-http` flag anywhere in `sbom scan --help`.
2. **custom / private CA unsupported (webpki-only)** — `registry.rs:84` builds
   `reqwest::Client::builder()` with no `.add_root_certificate(...)` and no
   `.danger_accept_invalid_certs(...)`. Workspace reqwest is `default-features=false` +
   `rustls-tls` (`Cargo.toml:16`) with `native-tls` deliberately NOT enabled
   (`waybill-cli/Cargo.toml:69`). rustls-tls trusts only the bundled webpki roots; there is no
   code path or flag to load an operator CA bundle.
3. **Bearer token unsupported in the credential chain** — the credential type is Basic-only:
   `struct Credential { username, secret }` (`auth.rs:43`). `resolve_credentials_layered`
   yields only docker-config/K8s `Basic` creds (or a docker `identitytoken` wrapped as
   `{username:"<token>", secret:token}`, `auth.rs:294`). A registry *Bearer challenge* is handled
   by exchanging those Basic creds at the token realm (`registry.rs:199 fetch_bearer_token`), but
   there is no way to *inject a pre-minted Bearer access token* as the input credential. This is
   why adapter D-2 returns 422 for a Bearer-type Harbor authorization.

## Offline enrichment anomaly — ROOT-CAUSED (updated)

The golang scan logged `ClearlyDefined enriched components ... count=16` despite
`WAYBILL_OFFLINE=1`. This is NOT a bundled dataset; it was a **live enrichment pass**. Root
cause, from source:

- The `--offline` clap arg has **no env binding** (`waybill-cli/src/main.rs:75-83`).
  `main.rs:280-284` bridges the *flag* to the env var (flag -> env), but there is no
  env -> flag path. So setting `WAYBILL_OFFLINE=1` in the environment never flips `cli.offline`.
- The three enrichment sources default **ON** (`resolve_enrich_sources`,
  `scan_cmd.rs:1389-1394`) and are gated on `cli.offline` (the flag), not the env var:
  `cli.offline` (`main.rs:355`) -> scan_cmd `execute` `offline` param (`:1767`) ->
  `ClearlyDefinedSource::new(offline)` (`:2252`), `DepsDevSource` (`:2236`),
  `deps_dev_graph` (`:2276`). Only the golang `graph_resolver`, `package_db`, and binary
  fingerprint paths read `WAYBILL_OFFLINE` from the env directly.
- Consequence: with only the env var set, every scan makes live outbound HTTPS calls to
  `deps.dev` and `clearlydefined.io`. Behind the planned NetworkPolicy those calls hang until
  client timeouts, pushing scans toward the 5m subprocess timeout, adding unbounded latency
  variance, and breaking the SSRF egress-control assumption (D-5).

**Fix (carried into M3):** the waybill wrapper must pass **`--offline` in argv**, not rely on
the env var. Keep `WAYBILL_OFFLINE=1` in the child-process env allowlist as well, because the
golang graph_resolver / package_db / binary-fingerprint paths only read the env var; belt and
suspenders. A component-tier assertion (M4) must prove a scan completes with egress blackholed.
This also amends D-5's allowlist note: `--offline` (flag) is the actual egress control, the env
var alone is insufficient.

**Status — IMPLEMENTED in M3.** `pkg/waybill/wrapper.go` prepends `--offline` to argv (before the
`sbom scan` subcommand, since it is a global flag) whenever enrichment is off, and keeps
`WAYBILL_OFFLINE=1` in the constructed child-env allowlist. Argv-level proof:
`pkg/waybill/wrapper_test.go:TestGenerateSBOM_ArgvHasOffline` asserts `--offline` is present and
precedes `sbom`. The env allowlist (never `os.Environ()`) is proven by
`TestGenerateSBOM_ChildEnvIsAllowlist` (adapter secrets do not leak; `WAYBILL_OFFLINE=1` present).

**Status — egress-blackholed component assertion IMPLEMENTED in M4.** `test/component/docker-compose.yml`
blackholes both waybill enrichment hosts (`api.deps.dev`, `api.clearlydefined.io`) to the RFC5737
unroutable address `192.0.2.1` via `extra_hosts` (a `connect()` there hangs, simulating the
production NetworkPolicy drop). `test/component/component_test.go:TestScanHappyPath...` completes a
full SBOM scan in ~2s under that blackhole; if `--offline` regressed, waybill would stall trying to
reach those hosts. `TestReadOnlyRootFilesystem` additionally asserts the `extra_hosts` blackhole is
wired. Real run: report-handler latency 7.4ms, raw report 48,635 B / gzip 6,949 B.

## Environment notes / things I could not verify

- Live `docker buildx imagetools inspect` of the published image: **not run** — package is private
  and the agent cannot complete an interactive `gh auth refresh -s read:packages` browser flow.
  Multi-arch + digest are from the release CI run log instead; runtime is proven against a
  checksum-verified byte-identical local reconstruction of the image.

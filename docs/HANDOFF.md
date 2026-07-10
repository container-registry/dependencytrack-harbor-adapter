# Implementation Handoff — mikebom-harbor-adapter

Prepared by the release-engineering agent. This is the state-of-the-branch record for
the owner who will publish the repo, cut the release, and deploy to demo.goharbor.io.

Every claim here was verified against the working tree, `git`, and the actual gate
commands on 2026-07-09. Where a claim is a design decision it cites the plan of record
(`.claude/plans/mikebom-harbor-adapter.md`).

## READ THIS FIRST — acceptance status and why the PR should open as a draft

Milestones **M1–M5 are complete and accepted**. **M7 (devenv e2e) is committed but was
HALTED at acceptance after 3 attempts** over blockers that are *not* inside this repo and
that a HARD RULE forbids this agent from fixing (do not modify `../harbor` or
`../dedicated-container-registry`). Open the PR as a **draft** until the owner clears them.

Outstanding M7 blockers (all outside this repo, none reference mikebom):

1. **`../harbor` working tree is not clean**, and the M7 gate literally requires
   `git -C ../harbor status --porcelain` to be empty. Verified now:
   ```
    M versions.env                                  # DELVE_VERSION v1.25.1 -> v1.27.0
   ?? src/server/registry/silent201_repro_test.go   # repro for goharbor PR #23375
   ```
   `grep -il mikebom` over both files returns nothing (exit 1): the delve bump is a Go
   debugger pin and the test file's own header says *"This file is temporary and not meant
   to be committed"* (goharbor PR #23375, dated Jul 2). Neither is M7 output. Owner fix:
   `git -C ../harbor checkout -- versions.env && rm ../harbor/src/server/registry/silent201_repro_test.go`
   (or stash), then the gate is clean.

2. **`../dedicated-container-registry` working tree is not clean**: three modified,
   unrelated tenant files (`c8n-prod25`, `c8n-stage`, `nifty-simplificator` `.secrets.yaml`).
   These are DCR/M9 scope, not M7. Owner reverts before treating the workspace as pristine.

3. **The M7 gate's literal wording — `sbom_overview.scan_status == Success` for both
   fixtures — is only transiently true.** Post-run the index reads `sbom_overview: null`.
   The durable, source-justified success signal is the per-child `sbom.harbor` accessory,
   which `run-e2e.sh` asserts. This is a **knowing deviation from the gate wording**,
   documented with harbor-source citations in `docs/harbor-behavior.md`
   (`base_controller.go:211-221`, `checker.go:125-134`). The SBOMs are genuinely produced;
   only the index-level status field is transient. Accept the per-child accessory as the
   gate, not the literal `sbom_overview`.

4. **`test/devenv/run-e2e.sh` is not reliably re-runnable (known residual defect, not
   fixed).** Line 107 asserts `.capabilities.support_sbom==true` from
   `GET /api/v2.0/scanners/{uuid}` exactly once, with no re-ping or retry. Harbor populates
   that field lazily, only after a successful capability ping. On a clean-shell re-run
   against an already-registered scanner whose adapter container was recreated, the field
   can read `null` and the script exits 1 *before any scan*. Workaround until fixed: hit
   `GET /api/v2.0/scanners/{uuid}/metadata` once (it re-pings the adapter) before rerunning,
   or add a poll-with-retry around line 107. This does not invalidate the produced SBOMs.

`../mikebom` is clean. **This repo's own working tree is clean** (`git status --porcelain`
empty). The blockers are entirely in sibling repos the owner controls.

## a. What exists now, per milestone (with commit hashes)

`git -C . log --oneline main..feat/initial-adapter`:

```
b7ce05d test(devenv): add Harbor devenv e2e harness (M7)
1ae6ae8 ci: add CI and release plumbing (M5)
f4c1b3d feat(test): add component test tier (M4)
ff66b06 feat(adapter): implement scanner adapter service (M3)
4093e67 feat(scaffold): repo scaffold and build tooling (M2)
2f2552f docs(spike): M1 decision spike + upstream gap filing
```

(`main` is a single empty `chore: initial commit` `ff3248b`; the six above are the branch.)

- **M1 — `2f2552f` — Decision spike + upstream filing.** `docs/spike-m1.md`,
  `docs/upstream-issues.md`. Proves valid SPDX 2.3 out of mikebom fed a docker-save
  tarball; records the mikebom pin (`v0.1.0-alpha.55`, digest
  `sha256:806521fba9319865d1b2f443e498f75a3a34878aaf2bda276356079be8ae2746`); measured SBOM
  sizes (golang:1.23 = 1,325 packages, 5,507,501 raw bytes, 1,054,388 gzip -9, 5.2x) that
  feed the gzip/Redis sizing decisions; files the three upstream mikebom v2 remote-pull
  enablers (insecure-registry, custom CA, Bearer). **Root-cause correction captured here:**
  `MIKEBOM_OFFLINE=1` does *not* disable enrichment egress; only the `--offline` argv flag
  does — the wrapper passes `--offline`.

- **M2 — `4093e67` — Repo scaffold + build tooling.** LICENSE, NOTICE, README,
  CONTRIBUTING, SECURITY, CODE_OF_CONDUCT; `go.mod`
  (`github.com/container-registry/mikebom-harbor-adapter`); `.golangci.yaml`, `.yamllint`,
  `.typos.toml`, `lefthook.yml`; `versions.env` (D-5 pins, no GO_VERSION);
  `Taskfile.yml` (git-describe versioning, D-9 task names); `Dockerfile` (multi-stage,
  distroless `cc-debian12:nonroot`, mikebom license files); `compose.yaml`; settings bundle
  under `.github`; `renovate.json` with a versions.env regex manager.

- **M3 — `ff66b06` — Adapter implementation.** `cmd/scanner-mikebom`, `pkg/etc`
  (config + startup checker), `pkg/harbor` (API models, `GetImageRef`), `pkg/http/api/v1`
  (metadata/scan/report/probes/metrics, gzip, Basic property, Bearer 422, vulnerability 422),
  `pkg/registry` (go-containerregistry pull -> docker-save tarball, D-1), `pkg/mikebom`
  (subprocess wrapper: env allowlist, `--offline`, `--timeout`, exit-124 classification,
  workdir lifecycle), `pkg/scan` (controller), `pkg/queue`, `pkg/persistence/{redis,memory}`,
  `pkg/job`, `pkg/redisx`; contract golden tests pinning the exact D-3 MIME strings and a
  `RawSBOMReport` round-trip against vendored Harbor `Validate()`.

- **M4 — `f4c1b3d` — Component tier.** `test/component`: compose of `registry:2` (htpasswd)
  + the real adapter image; full `POST -> 302 + Refresh-After -> 200` loop, failure path,
  read-only-rootfs assertion, report-size/gzip measurement, a VEX-producing fixture.

- **M5 — `1ae6ae8` — CI + release plumbing.** `.github/workflows` (ci, hygiene, pr-title,
  publish-image reusable WIF, main-image push+dispatch, release-please);
  `release-please-config.json` + `.release-please-manifest.json` seeded `0.0.0`;
  `docs/RELEASES.md`, `docs/INTEGRATION.md` (with the sbom-only footgun warning).

- **M7 — `b7ce05d` — Devenv e2e harness.** `test/devenv/run-e2e.sh`,
  `docs/harbor-behavior.md`. Committed; acceptance halted on the four blockers above.

### Final gate evidence (run 2026-07-09, this branch HEAD `b7ce05d`)

`task build`:
```
task: [build:binary:linux-arm64] go build -trimpath -buildvcs=false -ldflags "... -X main.version=b7ce05d ..." -o bin/linux-arm64/scanner-mikebom ./cmd/scanner-mikebom
Binaries:
-rwxr-xr-x  1 vadim  staff    16M  bin/linux-arm64/scanner-mikebom
```

`task test` (all packages pass; `-short -race`):
```
ok  github.com/container-registry/mikebom-harbor-adapter/cmd/scanner-mikebom       coverage: 0.0%
ok  github.com/container-registry/mikebom-harbor-adapter/pkg/etc                   coverage: 57.4%
ok  github.com/container-registry/mikebom-harbor-adapter/pkg/harbor                coverage: 81.8%
ok  github.com/container-registry/mikebom-harbor-adapter/pkg/http/api              coverage: 22.5%
ok  github.com/container-registry/mikebom-harbor-adapter/pkg/http/api/v1           coverage: 81.7%
ok  github.com/container-registry/mikebom-harbor-adapter/pkg/mikebom               coverage: 88.1%
ok  github.com/container-registry/mikebom-harbor-adapter/pkg/persistence/memory    coverage: 94.3%
ok  github.com/container-registry/mikebom-harbor-adapter/pkg/queue                 coverage: 4.7%
ok  github.com/container-registry/mikebom-harbor-adapter/pkg/registry              coverage: 92.3%
ok  github.com/container-registry/mikebom-harbor-adapter/pkg/scan                  coverage: 78.8%
ok  github.com/container-registry/mikebom-harbor-adapter/test/contract             coverage: [no statements]
```
Note: `task test` must run with the command sandbox disabled locally. Several tests
(`pkg/registry`, `test/contract`) spin up `httptest` servers; under the sandbox the bind
fails with `listen tcp6 [::1]:0: bind: operation not permitted` — a sandbox denial, not a
test defect. CI runners have no such restriction.

## b. What was deliberately NOT done — and the exact owner commands

M6, M8, M9, M10 involve network actions (repo creation, image publish, release, deploy) and
are the owner's to run. None were performed.

### M8 — cut the first release (needs M5, M6, M7)
Release-please owns tags; do not hand-tag.
```
# 1. Merge the scaffold feat: PR into main (squash).
# 2. release-please opens a "chore: release 0.1.0" PR. Verify it computes v0.1.0
#    (manifest seeded 0.0.0 -> first feat: proposes v0.1.0, not 1.0.0).
#    If it misbehaves, add a `Release-As: 0.1.0` footer commit on main (docs/RELEASES.md).
# 3. Merge the release PR (squash). The release-please job tags v0.1.0 and invokes
#    publish-image.yml (multi-arch build, cosign sign by digest, SPDX attestation).
# Post-release verification:
cosign verify --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*' \
  8gears.container-registry.com/8gcr/mikebom-harbor-adapter@<digest>
cosign verify-attestation --type spdx <same digest>
docker buildx imagetools inspect 8gears.container-registry.com/8gcr/mikebom-harbor-adapter:v0.1.0  # multi-arch
```

### M9 — deploy to demo.goharbor.io via the deployment engine (needs M8)
Cluster context comes from the engine (`aws eks update-kubeconfig` + tenant
`cloud_provider: aws-harbor-cr-prod-eu-central`). **Prerequisite: the `deployment.bot` EKS
access entry must exist** or kubectl is Unauthorized during deploy (see MEMORY:
dcr-deploy-bot-eks-access-entry):
```
aws eks list-access-entries \
  --cluster-name cr-eks-harbor-prod-eu-central-eksCluster-d382e91 \
  --region eu-central-1
# must list the IAM principal for deployment.bot; if absent, create the access entry first.
```
Then, in `dedicated-container-registry`:
```
# Edit the tenant overlay (SOPS): add values_overlay.extraManifests (block in section d below).
SOPS_AGE_KEY=<key> sops data/tenants/demo-goharbor.secrets.yaml
# Verify the in-namespace Valkey service name live before finalizing SCANNER_REDIS_URL.
# Add an extraManifests render test at tests/deployment_engine/test_harbor.py (M9 requires it;
#   harbor-next is the chart — confirm it renders .Values.extraManifests before real deploy).
python -m deployment_engine deploy -c aws-harbor-cr-prod-eu-central -t demo-goharbor --dry-run
python -m deployment_engine deploy -c aws-harbor-cr-prod-eu-central -t demo-goharbor
```
Deploy applies settings via `apply-settings`, which requires the **`SETTINGS_TOKEN`**
ops secret to be present.

### M10 — register the scanner + smoke + closeout (needs M9)
```
# Register mikebom as an additional NON-DEFAULT scanner (API key if SCANNER_API_AUTH_API_KEY set),
#   create project zz-mikebom-smoke, bind, crane-push alpine, trigger {"scan_type":"sbom"},
#   assert additions/sbom serves valid SPDX 2.3, delete the smoke project (registration survives).
bash scripts/c8n-smoke.sh demo.goharbor.io admin "$ADMIN_PASSWORD" zz-smoke   # regression
# Confirm the three upstream mikebom issues are still filed. Commit the tenant file.
```

## c. The 8gears FedIDP robot that MUST exist before any image publish

**Nothing publishes to `8gcr` until this federated robot exists.** `publish-image.yml`
mints a GitHub OIDC token and logs in to `8gears.container-registry.com` with
`username: jwt`, password = the OIDC token (keyless WIF). Required config on
`8gears.container-registry.com` (see MEMORY: 8gears-registry-fedidp):

- **Global GitHub OIDC provider** configured.
- **Claim rule:** `repository == container-registry/mikebom-harbor-adapter`.
- **Audience:** `https://8gears.container-registry.com`.
- **Permission:** push on project `8gcr`.

Until this robot exists, `main-image.yml` `workflow_dispatch` (the WIF smoke) and every
release publish will fail at `docker login`. This is M6 ops work and has not been done.

## d. demo.goharbor.io extraManifests block

Paste under `values_overlay.extraManifests` in
`dedicated-container-registry/data/tenants/demo-goharbor.secrets.yaml`. This is a **ready
template**, not yet applied; M9 must (i) confirm the `harbor-next` chart (v2.0.0) actually
renders `.Values.extraManifests` via the render test, (ii) verify the live Valkey service
name (`registry.config.redis.addr` in this tenant is `valkey:6379`), and (iii) pin the
image tag to the released `v0.1.0`. The workdir is a **disk-backed** emptyDir with a
`sizeLimit` (NOT `medium: Memory`): a memory-medium emptyDir and tmpfs both count against
the 1Gi container limit and OOM-kill on mid-size images (open perf finding M1/major, M4/major).

```yaml
    extraManifests:
      - apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: mikebom-adapter
          namespace: demo-goharbor
          labels: { app: mikebom-adapter }
        spec:
          replicas: 1                      # single replica in v1 (D-8)
          selector: { matchLabels: { app: mikebom-adapter } }
          template:
            metadata:
              labels: { app: mikebom-adapter }
            spec:
              imagePullSecrets:
                - name: 8g-registry-secret
              securityContext:
                runAsNonRoot: true
                runAsUser: 65532
                runAsGroup: 65532
                fsGroup: 65532
              containers:
                - name: adapter
                  image: 8gears.container-registry.com/8gcr/mikebom-harbor-adapter:v0.1.0
                  imagePullPolicy: IfNotPresent
                  ports:
                    - { name: http, containerPort: 8080 }
                  env:
                    - { name: SCANNER_API_SERVER_ADDR, value: ":8080" }
                    - { name: SCANNER_REDIS_URL, value: "redis://valkey:6379" }   # verify service name live
                    - { name: SCANNER_STORE_REDIS_NAMESPACE, value: "harbor.scanner.mikebom:data-store" }
                    - { name: SCANNER_JOB_QUEUE_REDIS_NAMESPACE, value: "harbor.scanner.mikebom:job-queue" }
                    - { name: SCANNER_MIKEBOM_WORK_DIR, value: "/home/scanner/work" }
                    - { name: SCANNER_JOB_QUEUE_WORKER_CONCURRENCY, value: "1" }
                    # Optional API-key auth (SSRF mitigation); set to a sops secret if used:
                    # - { name: SCANNER_API_AUTH_API_KEY, value: "<secret>" }
                  securityContext:
                    readOnlyRootFilesystem: true
                    allowPrivilegeEscalation: false
                    capabilities: { drop: ["ALL"] }
                  volumeMounts:
                    - { name: work, mountPath: /home/scanner }
                  readinessProbe:
                    httpGet: { path: /probe/ready, port: http }
                    initialDelaySeconds: 3
                    periodSeconds: 10
                  livenessProbe:
                    httpGet: { path: /probe/healthy, port: http }
                    initialDelaySeconds: 5
                    periodSeconds: 20
                  resources:
                    requests: { cpu: 50m, memory: 128Mi }
                    limits:   { cpu: "1",  memory: 1Gi }
              volumes:
                - name: work
                  emptyDir:
                    sizeLimit: 5Gi          # disk-backed, NOT medium: Memory (perf finding)
      - apiVersion: v1
        kind: Service
        metadata:
          name: mikebom-adapter
          namespace: demo-goharbor
        spec:
          selector: { app: mikebom-adapter }
          ports:
            - { name: http, port: 8080, targetPort: http }
      - apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: mikebom-adapter
          namespace: demo-goharbor
        spec:
          podSelector: { matchLabels: { app: mikebom-adapter } }
          policyTypes: ["Ingress"]
          ingress:
            - from:
                - podSelector: { matchLabels: { component: core } }
                - podSelector: { matchLabels: { component: jobservice } }
              ports:
                - { protocol: TCP, port: 8080 }
```
Register (M10) with `url: http://mikebom-adapter.demo-goharbor:8080` (or
`use_internal_addr: true`; D-1 handles the hairpin `https://demo.goharbor.io` pull path).
Verify the `component:` label selectors match the harbor-next pod labels before relying on
the NetworkPolicy (harbor-next may label differently than upstream goharbor).

## e. Residual risks, open performance findings, open owner questions, deviations

### Knowing deviations from the plan of record
- **M7 gate wording vs reality:** the index `sbom_overview.scan_status == Success` is
  transient; accepted signal is the per-child `sbom.harbor` accessory (source-justified in
  `docs/harbor-behavior.md`). See blocker 3.
- **`MIKEBOM_OFFLINE=1` is not the egress control** (plan D-5/D-7 assumed it was); the
  wrapper passes `--offline` in argv. Env var kept for the golang graph_resolver /
  package_db / binary-fingerprint paths that do read it. Captured in `docs/spike-m1.md` and
  D-5 was amended in the plan.
- **mikebom image path is `ghcr.io/kusari-oss/mikebom`** (org renamed from `kusari-sandbox`
  in the original plan text). `versions.env` uses the correct `kusari-oss` path.

### Open owner questions (defaults proceeded; owner may override)
- **Q-1** scanner identity strings — proceeded with `name: mikebom`, `vendor: Kusari`.
- **Q-2** image project — proceeded with `8gcr`.
- **Q-4** demo scope — proceeded with additional non-default, project-bound scanner.
- **Q-5** mirror mikebom image into 8gears vs digest-pin ghcr — proceeded with digest pin;
  mirroring is a one-line `crane copy` follow-up.

### Residual risk: sbom-only footgun
This scanner has **no vulnerability capability**. If it becomes a project's scanner, every
vulnerability path for that project degrades: explicit vuln triggers return HTTP 500,
auto-scan and Scan All silently produce no vulnerability data (verified in
`docs/harbor-behavior.md` section 2). Register additional, non-default, project-bound.

### Residual defect: run-e2e.sh re-runnability
See blocker 4. The committed script asserts the lazily-cached `support_sbom` field once; a
clean-shell re-run can fail before scanning. Not fixed. Workaround documented above.

### Open performance findings (carried, not fixed; ranked by severity)
These are known and deferred. None block a draft PR; several should be addressed before a
production (non-demo) rollout.

Blocker/major (address before scaling beyond single-replica demo):
- **Queue is Redis Pub/Sub — silent job loss.** go-redis buffers 100 messages, drops after
  60s full; an adapter restart loses every queued/in-flight job (they sit Queued until the
  1h TTL while Harbor polls). Backlog >~101 with 1 worker at minutes-per-scan starts
  dropping. Fix: switch to a Redis list/stream (LPUSH/BRPOPLPUSH); the SetNX lock already
  dedupes. (M3/M4/M5)
- **Per-job workdir is unbounded and, in the shipped compose harnesses, RAM-backed tmpfs.**
  No image-size cap or free-space check before pull; `/scan` accepts attacker-influenced
  registry URLs (SSRF surface). A multi-GB image can OOM the pod instead of failing cleanly.
  Fix: sum manifest layer sizes and reject above a configurable cap; use disk-backed
  emptyDir with sizeLimit in K8s (encoded in the block above), add `size=` to compose tmpfs.
  (M1/M2/M4)
- **No pull-phase deadline distinct from the job deadline.** A stalled pull with
  concurrency=1 halts all scanning until restart. Fix: dedicated `SCANNER_PULL_TIMEOUT`, set
  LockTTL = pull budget + mikebom timeout + margin (strictly longer than the job deadline).
  (M3/M4)
- **Report I/O amplification + uncompressed Redis storage.** The finish path moves the
  multi-MB SBOM across Redis ~4x via read-modify-write, stored raw (~5.5 MB golang vs ~1 MB
  gzipped). Bounded by go-redis per-command timeouts. Fix: single SetXX at finish, gzip the
  stored envelope. (M3/M4/M5)
- **Throughput mismatch.** Adapter is serial (concurrency 1) while Harbor jobservice runs
  many scan jobs in parallel, each polling ≤30 min; jobs whose wait exceeds 30 min are
  abandoned by Harbor but still fully executed by the adapter (wasted CPU/egress). Fix:
  document sizing rule in `docs/INTEGRATION.md`, consider raising default concurrency, or
  skip jobs older than Harbor's 30-min budget. (M5)

Minor (correctness/cost hygiene):
- Harbor parses `Refresh-After` as int8 (>127 silently falls back to 5s polling); keep the
  value ≤127 and add a bound test. (M1/M2)
- `SCANNER_MIKEBOM_TIMEOUT=0` is accepted and collapses LockTTL to 30s; reject `<= 0`. (M5)
- Redis pool timeout knobs are ignored for the standalone `redis://` scheme (only sentinel
  wires them); go-redis defaults apply. Wire them or document. (M5)
- Backstop kill reaps only the direct child, not the process group; set `Setpgid` + a
  group-kill `Cancel`. (M3)
- CI cost: golangci-lint/govulncheck compiled from source each run; QEMU installed in
  publish-image though the Dockerfile has no RUN steps (binaries are cross-compiled and
  COPY'd). Install lint tools from release binaries; drop setup-qemu. (M4/M5)
- lprobe adds ~12 MB/arch to probe an endpoint the adapter serves; a `-healthcheck` self-probe
  flag could drop it. (M2)

Full detail for each finding is in the milestone reports under
`.claude/plans/mikebom-harbor-adapter/`.

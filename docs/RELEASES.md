# Releasing mikebom-harbor-adapter

Releases are automated with [release-please](https://github.com/googleapis/release-please).
A merge to `main` updates (or opens) a release PR; merging that release PR tags the
version and triggers the image publish. You do not tag or build releases by hand.

## Flow

1. Land changes on `main` via **squash merge** of a conventional-commit PR.
2. release-please maintains a `chore: release <version>` PR with the computed next
   version, `CHANGELOG.md`, and `.release-please-manifest.json` bumped.
3. Merge that release PR. The `release-please` job then:
   - creates the git tag (`v<version>`, `include-v-in-tag`),
   - calls `publish-image.yml` to build and push the multi-arch image, cosign-sign it
     by digest, and attach an SPDX attestation,
   - appends the Container Image table and verification snippets to the release notes.

## Versioning

- `release-type: go`, default semantics: `feat:` -> minor, `fix:`/`perf:` -> patch.
- `bump-minor-pre-major: true`: while pre-1.0, a breaking `feat!:` bumps the minor, it
  does not jump to 1.0.0.
- The manifest is seeded at `0.0.0`, so the first `feat:` release proposes **v0.1.0**
  (not release-please's default 1.0.0). There is no `v0.0.0` tag; that is harmless.

## Hard rules

- **Squash-merge only.** Merge commits break release-please's commit parsing. Rebase
  merges are also disabled in repo settings. This is load-bearing, not a preference.
- **Never push `v*` tags by hand.** release-please owns the tags. A hand-pushed tag
  desynchronizes the manifest and the next release PR will compute the wrong version.
- **No AI attribution / `Co-Authored-By` trailers.** DCO sign-off is enforced by
  lefthook + the hygiene job.

## The `exclude-paths` gotcha (read this before a docs/CI-only PR)

`release-please-config.json` sets `"exclude-paths": [".github", "docs"]`. A commit that
touches **only** files under `.github/` or `docs/` does **not** bump the version, even if
it is typed `feat:` or `fix:`. This is deliberate: workflow and documentation churn must
not cut a release.

Consequence for PR titles:

- Changes under `.github/` -> type them `ci:`.
- Changes under `docs/` -> type them `docs:`.

Both `ci:` and `docs:` are hidden changelog sections, so they will not produce noise even
if they did land in a mixed release. If you type a `.github/`-only or `docs/`-only change
as `feat:` expecting a release, nothing will happen and it will look like release-please
is broken. It is not; the path is excluded.

## Manual step per release: the demo tenant image tag

The demo.goharbor.io deployment pins the adapter image tag in the tenant overlay
(`dedicated-container-registry` -> `data/tenants/demo-goharbor.secrets.yaml`,
`values_overlay.extraManifests`). release-please does **not** reach into that repo. After a
release, bump the image tag there to the new `v<version>` and run the deploy. This is a
documented manual step, one per release.

## If the 0.0.0 bootstrap misbehaves

If the first release PR does not compute `v0.1.0`, force it with a
`Release-As: 0.1.0` footer in a commit on `main`, or re-seed
`.release-please-manifest.json`. Do not hand-tag as a workaround.

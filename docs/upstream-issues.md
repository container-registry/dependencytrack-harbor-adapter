# Upstream waybill issues

The upstream project was renamed: `kusari-oss/mikebom` is now
[`kusari-oss/waybill`](https://github.com/kusari-oss/waybill). The crates are
`waybill-cli` / `waybill-common`, the binary is `waybill`, and release assets are
named `waybill-*` from `v0.1.0-alpha.66` onwards (`mikebom-*` up to `alpha.65`).

Three issues were identified against `v0.1.0-alpha.55` as the v2 remote-pull
enablers. While either of the first two was open, waybill could not pull from a
typical Harbor registry, so the adapter pulled the artifact itself with
go-containerregistry and handed waybill a docker-save tarball (plan D-1).

**Issues 1 and 2 are resolved upstream** by waybill milestone 182, and the D-1
workaround has been removed: the adapter now runs
`waybill sbom scan --image <ref> --image-src remote` and waybill performs the
pull. Issue 3 (caller-supplied Bearer token) is still open and still constrains
the adapter to Basic and anonymous authorization.

| # | Issue | Status |
|---|-------|--------|
| 1 | Cannot pull from a plain-HTTP (insecure) registry | **Resolved** — m182 `--insecure-registry <host[:port]>` |
| 2 | No way to trust a custom / private CA | **Resolved** — m182 `--registry-ca-cert <path>` (+ `--insecure-tls-skip-verify`) |
| 3 | Credential chain accepts Basic only; no pre-minted Bearer token | **Open** — `Credential` is still `{username, secret}` |

---

## Issue 1 — plain-HTTP (insecure) registries — RESOLVED

waybill `--image-src remote` used to hardcode `https://` for the OCI distribution
API (`mikebom-cli/src/scan_fs/oci_pull/registry.rs:455,464` at `alpha.55`), so an
image on a plain-HTTP registry could not be scanned. The Harbor devenv advertises
`registry.url = http://core:8080`, which is exactly that case.

Milestone 182 added a repeatable `--insecure-registry <HOST[:PORT]>` flag. The
scheme is chosen per URL by `scheme_for_registry`
(`waybill-cli/src/scan_fs/oci_pull/registry.rs`) against a matcher built in
`tls_config.rs`. Host-only matches any port, `host:port` matches that port only,
and matching is on the user-facing registry name typed in `--image` — `docker.io`
does not auto-expand to `registry-1.docker.io`. `https://` remains the default, so
a missing flag can never silently downgrade a production pull.

**Adapter use:** `pkg/waybill/wrapper.go` passes `--insecure-registry <host:port>`
whenever Harbor's `registry.url` scheme is `http`, deriving the host from the same
reference string it hands to `--image`.

## Issue 2 — custom / private CA — RESOLVED

waybill's OCI client trusted only the bundled webpki (Mozilla) roots, with no flag
or env var to add a private CA, so any registry served from a corporate PKI failed.

Milestone 182 added a repeatable `--registry-ca-cert <PATH>` (each file may be a
multi-certificate PEM bundle; all certificates are loaded) plus
`--insecure-tls-skip-verify` as the explicitly-unsafe escape hatch, which logs a
WARN at scan start. The CA-bundle path fails fast: a missing, empty or non-PEM
file errors before any network call, naming the offending path.
`--insecure-tls-skip-verify` does not fail anything — it deliberately succeeds
with verification disabled, which is exactly why it is the unsafe escape hatch.

**Adapter use:** `SCANNER_WAYBILL_REGISTRY_CA_CERTS` (comma-separated) becomes one
`--registry-ca-cert` per path, and `SCANNER_WAYBILL_INSECURE_TLS_SKIP_VERIFY=true`
adds `--insecure-tls-skip-verify`. The adapter also stats every CA path at startup
(`pkg/etc/checker.go`), so a bad path is a failed deployment rather than a failed
scan.

### Verified behavior (waybill 0.1.0-alpha.69)

Run against a local `registry:2` — plain HTTP with htpasswd on `:5555`, and TLS
with a self-signed private CA on `:5556`:

| Case | Flags | Result |
|------|-------|--------|
| plain HTTP, no flag | — | `Error: TLS handshake failed ... pass --insecure-registry localhost:5555` |
| plain HTTP, no creds | `--insecure-registry localhost:5555` | `Error: registry returned 401 with Basic auth challenge ... no credentials are configured` |
| plain HTTP + creds | `--insecure-registry` + `WAYBILL_REGISTRY_USERNAME/_PASSWORD` | exit 0, SPDX with 17 packages |
| private CA, no flag | — | `Error: TLS certificate chain validation failed ... pass --registry-ca-cert <path>` |
| private CA | `--registry-ca-cert ca.crt` | exit 0, SPDX written |
| private CA | `--insecure-tls-skip-verify` | exit 0, SPDX written |
| bad CA path | `--registry-ca-cert /nonexistent.pem` | exit 1 before any network call, names the path |

Credential env keys were confirmed to include the port:
`WAYBILL_REGISTRY_LOCALHOST_5555_USERNAME` resolves,
`WAYBILL_REGISTRY_LOCALHOST_USERNAME` does not. `pkg/waybill.registryEnvKey`
mirrors that derivation and is unit-tested against it.

---

## Issue 3 — credential chain accepts Basic only — STILL OPEN

**Labels:** enhancement, oci-pull, auth

### Summary

The OCI credential chain resolves username/password (Basic) style credentials
only. There is no way to hand waybill an already-issued Bearer/registry access
token to send directly. Callers that receive a short-lived Bearer token from an
upstream (e.g. a robot/OIDC token minted out of band) cannot use it: waybill can
only take a `username:secret` pair and perform its own token exchange.

### Where (v0.1.0-alpha.69)

`waybill-cli/src/scan_fs/oci_pull/auth.rs`:

```rust
pub(super) struct Credential {
    pub(super) username: String,   // Basic only
    pub(super) secret: String,
}
```

Milestone 182 and issue #235 widened where credentials come from — per-registry
`WAYBILL_REGISTRY_<HOST>_USERNAME`/`_PASSWORD`, generic
`WAYBILL_REGISTRY_USERNAME`/`_PASSWORD`, `--registry-credentials-dir`, then the
Docker config — but not what shape they take. When a registry issues a **Bearer
challenge**, waybill exchanges those Basic credentials at the token realm
(`registry.rs fetch_bearer_token`); it never accepts a caller-supplied Bearer
token as input.

### Proposed change

Extend the credential input to allow a raw Bearer token, e.g. a
`--registry-bearer-token <token>` flag (or `WAYBILL_REGISTRY_BEARER_TOKEN` env
var) that is sent verbatim as `Authorization: Bearer <token>` on manifest/blob
requests, bypassing the token exchange. This matches how scanner integrations
forward a short-lived registry token they already hold.

### Impact on this adapter

The adapter rejects Bearer-type authorizations with HTTP 422 at `/api/v1/scan`
(plan D-2) and relies on Basic-decoded credentials only. This is unchanged by the
move to native remote pull: the credentials still have to be a username/password
pair for waybill to exchange. Supporting a supplied Bearer token would let the
adapter reuse Harbor's own token instead of re-authenticating.

# Upstream mikebom issues (to file against kusari-oss/mikebom)

These are the texts of three issues to file upstream. They are the v2 remote-pull enablers
referenced by the mikebom-harbor-adapter plan (D-1): while any of them is open, mikebom cannot
pull directly from a typical Harbor registry, so the adapter pulls the artifact itself and hands
mikebom a docker-save tarball. All three are confirmed against mikebom at tag `v0.1.0-alpha.55`.

Filing is deferred (M6/M10 own the actual filing); this file is the source of truth for the text.

---

## Issue 1 — `sbom scan --image <ref>` cannot pull from a plain-HTTP (insecure) registry

**Labels:** enhancement, oci-pull

### Summary
`mikebom sbom scan --image <ref> --image-src remote` always uses `https://` for the OCI
distribution API. There is no way to scan an image hosted on a plain-HTTP registry, which is the
default for local/dev registries (e.g. a Harbor devenv that advertises `registry.url =
http://core:8080`, or an in-cluster registry reached over HTTP).

### Where (v0.1.0-alpha.55)
`mikebom-cli/src/scan_fs/oci_pull/registry.rs`:

```rust
fn manifest_url(reference: &ImageReference) -> String {
    let registry = resolve_registry_for_url(&reference.registry);
    format!("https://{registry}/v2/{}/manifests/{}", ...)   // line 455: https hardcoded
}
fn blob_url(reference: &ImageReference, digest: &str) -> String {
    let registry = resolve_registry_for_url(&reference.registry);
    format!("https://{registry}/v2/{}/blobs/{}", ...)        // line 464: https hardcoded
}
```

`sbom scan --help` exposes no `--insecure-registry` / `--plain-http` flag, and no env var toggles
the scheme.

### Proposed change
Add an opt-in `--insecure-registry <host[:port]>` flag (repeatable) and/or a `--plain-http` flag,
mirroring `crane --insecure`, `skopeo --src-tls-verify=false`, and `trivy --insecure`. When a
target registry matches, build `http://` manifest/blob URLs. Keep `https://` the default; the flag
must be explicit per host so a typo never silently downgrades a production pull.

### Impact
Blocks scanning images from plain-HTTP registries entirely. It is one of the reasons the Harbor
adapter pulls the artifact itself instead of using `--image-src remote`.

---

## Issue 2 — no way to trust a custom / private CA (rustls webpki roots only)

**Labels:** enhancement, oci-pull, tls

### Summary
mikebom's OCI client trusts only the bundled webpki (Mozilla) root set. There is no flag or env var
to add a private/corporate CA bundle, so `sbom scan --image <ref> --image-src remote` fails against
any registry served with a certificate chained to a private CA (internal Harbor/Quay/Nexus behind
a corporate PKI, or a registry with a self-signed/enterprise root).

### Where (v0.1.0-alpha.55)
`mikebom-cli/src/scan_fs/oci_pull/registry.rs:84`:

```rust
let http = reqwest::Client::builder()
    .user_agent(concat!("mikebom/", env!("CARGO_PKG_VERSION")))
    .build()                                   // no .add_root_certificate(), no custom trust
    .context("building reqwest::Client for OCI registry")?;
```

Workspace reqwest is configured `default-features = false` with `rustls-tls`
(`Cargo.toml:16`), and `native-tls` is deliberately not enabled (`mikebom-cli/Cargo.toml:69`), so
the system trust store is not consulted either. There is no code path that loads an operator CA.

### Proposed change
Add `--registry-ca-cert <path>` (repeatable, PEM bundle) that calls
`reqwest::Certificate::from_pem` + `ClientBuilder::add_root_certificate`, and honor the de-facto
`SSL_CERT_FILE` / a `MIKEBOM_REGISTRY_CA_BUNDLE` env var. Optionally add
`rustls-tls-native-roots` behind a feature so the OS trust store can be used. Do not add a blanket
"disable verification" as the primary answer; a CA-bundle path is the safe fix.

### Impact
Blocks scanning any registry fronted by a private CA. Combined with Issue 1, it means remote-pull
is unusable in most self-hosted Harbor deployments, which is why the adapter materializes the
tarball itself.

---

## Issue 3 — credential chain accepts Basic only; cannot supply a pre-minted Bearer token

**Labels:** enhancement, oci-pull, auth

### Summary
The OCI credential chain resolves username/password (Basic) style credentials only. There is no way
to hand mikebom an already-issued Bearer/registry access token to send directly. Callers that
receive a short-lived Bearer token from an upstream (e.g. Harbor's scan-adapter API passes a Bearer
authorization, or a robot/OIDC token minted out of band) cannot use it: mikebom can only take a
`username:secret` pair and perform its own token exchange.

### Where (v0.1.0-alpha.55)
`mikebom-cli/src/scan_fs/oci_pull/auth.rs:43`:

```rust
pub(super) struct Credential {
    pub(super) username: String,   // Basic only
    pub(super) secret: String,
}
```

`resolve_credentials_layered` produces only Basic credentials from docker config / K8s
`dockerconfigjson` secrets (a docker `identitytoken` is wrapped as
`{username:"<token>", secret:token}`, `auth.rs:294`). When a registry issues a **Bearer
challenge**, mikebom exchanges those Basic creds at the token realm
(`registry.rs:199 fetch_bearer_token`) — it never accepts a caller-supplied Bearer token as input.

### Proposed change
Extend the credential input to allow a raw Bearer token, e.g. a `--registry-bearer-token <token>`
flag (or `MIKEBOM_REGISTRY_BEARER_TOKEN` env var, or a `<token>`-style credential form) that is
sent verbatim as `Authorization: Bearer <token>` on manifest/blob requests, bypassing the token
exchange. This matches how scanner integrations forward a short-lived registry token they already
hold.

### Impact
Forces the Harbor adapter to reject Bearer-type authorizations (D-2: return HTTP 422) and to rely
on Basic-decoded credentials only. Supporting a supplied Bearer token would let a future
`--image-src remote` path reuse Harbor's own token instead of re-authenticating.

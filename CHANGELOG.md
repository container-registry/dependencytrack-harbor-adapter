# Changelog

## 1.0.0 (2026-08-20)


### ⚠ BREAKING CHANGES

* module path, binary name, image name and every SCANNER_MIKEBOM_* env var are renamed to their waybill equivalents.

### Features

* **adapter:** implement scanner adapter service (M3) ([ff66b06](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/ff66b060ece41763198f9b949900458881de947b))
* add adapter metrics and collapse the report write path ([cf4ca4e](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/cf4ca4e32a1a8b3e8881ea9763f6336200f934cf))
* fork waybill-harbor-adapter into a Dependency-Track adapter ([14d3bd8](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/14d3bd8867341b4afec4145aa0c2e76cc4ddcdf7))
* reject oversized artifacts before the pull, and bound decompression ([0bdfccd](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/0bdfccde546cb34874efcb71303b7afb7934df5c))
* rename to waybill, use its native registry pull, address review ([762af4e](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/762af4eb513e76d18d177cf7656251178f85b9d9))
* **scaffold:** repo scaffold and build tooling (M2) ([4093e67](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/4093e676aec62bf9c64bce8d165c47f419d10da4))
* **test:** add component test tier (M4) ([f4c1b3d](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/f4c1b3d8688fe24e604a7fc4f4a4a74930ce03d9))
* waybill Harbor scanner adapter (SBOM-only) ([b3376f7](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/b3376f7b5f7286265f74a9e1e44daf3cbbf7e4ec))


### Bug Fixes

* address Copilot review findings on PR [#1](https://github.com/container-registry/dependencytrack-harbor-adapter/issues/1) ([ceac2d3](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/ceac2d30a48801a595f1dc7805e0fe4f5914fe37))
* address open PR review findings (queue crash recovery, atomic store writes, submit-time validation) ([50045b2](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/50045b2e7882e554f57906b6b45fe5866f7a239a))
* **build:** source mikebom from its public release tarball ([c3d81f8](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/c3d81f804fc6df0d782f64e0356abbe070322391))
* **ci:** resolve lint, spellcheck, and govulncheck failures ([1d8ccd9](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/1d8ccd9b92f7fd6b104e68bff1825d7de44faee6))
* close a size-cap bypass and seven correctness gaps from PR review ([64654de](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/64654de126710fc37d30a5d3740d1c3eba483ec5))
* **imageprobe:** close two guard bypasses and correct the memory pairing ([9689fca](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/9689fcafd20f4e8d196ffa30b61f684799f4de44))
* make SCANNER_STORE_BACKEND=memory actually run scans ([00bbfa7](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/00bbfa71427efca8379072e64801ff76e05c6777))
* **queue:** make the job list FIFO, and bound worker shutdown ([9ed3b62](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/9ed3b62718bb5a5ac5f9181d93ed760919113257))
* recover from a missing Dependency-Track parent, and document when the fast path can fire ([e4b76e6](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/e4b76e6a5a85b68af7afe079222301bbbf2c6f7e))
* repair two regressions from the last push, and five interop bugs ([62df7d6](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/62df7d6a6afbbb512aeee32dc8b5b54cf40b5b11))
* report queued-job expiry separately, and correct the capacity guidance ([566c869](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/566c869cb90926b921bc63727dd2977b574bf94f))
* stop exec'ing waybill --version twice, and make dev:up build waybill ([6287d24](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/6287d2484b02e254c4c39b1edf910e04af2f4d42))
* **test:** pin tmpfs mode=1777 for the adapter work dir ([f34780b](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/f34780b8b389be391cf5b802950c26bc318a4778))


### Documentation

* note the tmpfs memory cost in compose.yaml ([e1fcee1](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/e1fcee12f22a87a6b006e2f05e4efca7cabc40f7))
* rewrite for the waybill rename and native registry pull ([3c76a2e](https://github.com/container-registry/dependencytrack-harbor-adapter/commit/3c76a2ed70ea85e8cfebb64e3b1fe091f7816eea))

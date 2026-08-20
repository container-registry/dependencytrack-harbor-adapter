// Package imageprobe reads an artifact's manifest to learn how big it is before
// syft is asked to pull it.
//
// It exists because memory is the binding constraint and nothing else bounds it.
// syft holds layer content in memory during the pull, so peak RSS runs at
// ~4.7x the compressed size: golang:1.24 (316 MB) peaks at 1.32 GiB, node:22
// (400 MB) at 1.75 GiB, and nvidia/cuda:12.6.3-devel (3.7 GB) is still
// OOM-killed at a 7Gi limit. The kill lands on the container, not on the job, so
// one oversized artifact takes every in-flight scan down with it and the pod
// restarts. A cheap manifest read turns that into one typed rejection.
//
// This is a manifest request, not a pull: one GET of a few kilobytes, no blobs.
// That is the whole reason go-containerregistry is acceptable back on the
// runtime path after the switch to syft's native pull removed it — the thing
// that was expensive was fetching every layer twice, not reading a manifest.
//
// The registry is not trusted to be well-behaved. Sizes come from a document the
// remote controls, so an under-reported total is a way to defeat the guard: every
// descriptor is range-checked and the running total is overflow-checked, and
// anything that cannot be measured is an error rather than a zero.
package imageprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/etc"
)

// maxIndexDepth bounds nested-index recursion. Nesting is legal but vanishingly
// rare in practice; the bound is what stops a malicious registry from serving a
// self-referential index and turning the guard into an infinite walk.
const maxIndexDepth = 4

// maxPlausibleSize is an upper bound on any single descriptor, well above any
// real layer. A registry reporting more than this is malfunctioning or hostile,
// and either way the artifact is far past any cap worth configuring.
const maxPlausibleSize = int64(1) << 45 // 32 TiB

// Target is the artifact to measure, with the credentials and transport the pull
// would use. It mirrors syft.ScanTarget rather than importing it, so the
// probe does not depend on the scanner wrapper.
type Target struct {
	Ref      string
	Username string
	Password string
	Insecure bool
}

// TooLargeError is the typed rejection. It carries both numbers because the
// operator's next action depends on the ratio, not just the fact.
type TooLargeError struct {
	Ref   string
	Size  int64
	Limit int64
}

func (e *TooLargeError) Error() string {
	// Both knobs are named: raising the cap alone just moves the OOM back one
	// artifact.
	return fmt.Sprintf(
		"artifact %s is %d compressed bytes, over the %d limit; scanning it needs roughly %d bytes of memory "+
			"(raise SCANNER_SYFT_MAX_IMAGE_SIZE and the container memory limit together)",
		e.Ref, e.Size, e.Limit, EstimatedMemory(e.Size))
}

// memoryRatioNum/memoryRatioDen express the measured peak-RSS-to-compressed-size
// ratio, 4.7x. It is taken from the largest successful run rather than from an
// OOM ceiling: node:22 (400 MB) peaked at 1.75 GiB on a 4Gi limit, while the
// 1.65 GiB it used under a 2Gi limit only shows what it was squeezed into.
// Sizing off the squeezed number would under-provision by design.
const (
	memoryRatioNum = 47
	memoryRatioDen = 10
)

// EstimatedMemory is the RSS a scan of this many compressed bytes is expected to
// need. It saturates instead of wrapping: a pathological manifest would
// otherwise turn the operator guidance in TooLargeError into a negative number.
func EstimatedMemory(compressedSize int64) int64 {
	if compressedSize <= 0 {
		return 0
	}
	if compressedSize > math.MaxInt64/memoryRatioNum {
		return math.MaxInt64
	}
	return compressedSize * memoryRatioNum / memoryRatioDen
}

// Prober measures an artifact without pulling it.
type Prober interface {
	// CompressedSize is the total size of the layers syft would download. For
	// a multi-platform index it is the platform syft will resolve: the one
	// SCANNER_SYFT_IMAGE_PLATFORM names, or the largest when it names none.
	CompressedSize(ctx context.Context, target Target) (int64, error)
}

type prober struct {
	transport http.RoundTripper
	// platform mirrors SCANNER_SYFT_IMAGE_PLATFORM. Without it the probe
	// charges the largest child of an index, which would refuse an artifact
	// whose selected platform is comfortably under the cap.
	platform string
}

// New builds a Prober sharing the registry TLS settings the syft wrapper
// passes on the command line, so the probe and the pull trust the same roots.
func New(cfg etc.Syft) (Prober, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.InsecureSkipVerify {
		// Operator-selected, WARNed at startup by etc.Check, and the pull that
		// follows runs with --insecure-tls-skip-verify anyway: a probe that
		// verified more strictly than the pull would reject artifacts the scan
		// would then have handled fine.
		tlsConfig.InsecureSkipVerify = true // #nosec G402
	}

	if cfg.RegistryCACert != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(cfg.RegistryCACert)
		if err != nil {
			return nil, fmt.Errorf("reading registry CA cert %s: %w", cfg.RegistryCACert, err)
		}
		// AppendCertsFromPEM reports whether anything was added. Discarding it
		// turns a malformed bundle into a confusing handshake failure on every
		// scan instead of one startup error.
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("registry CA cert %s contains no usable certificate", cfg.RegistryCACert)
		}
		tlsConfig.RootCAs = pool
	}

	base, ok := remote.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("unexpected remote.DefaultTransport type %T", remote.DefaultTransport)
	}
	transport := base.Clone()
	transport.TLSClientConfig = tlsConfig

	return &prober{transport: transport, platform: strings.TrimSpace(cfg.Platform)}, nil
}

func (p *prober) CompressedSize(ctx context.Context, target Target) (int64, error) {
	var nameOpts []name.Option
	if target.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}
	ref, err := name.ParseReference(target.Ref, nameOpts...)
	if err != nil {
		return 0, fmt.Errorf("parsing artifact reference %q: %w", target.Ref, err)
	}

	remoteOpts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithTransport(p.transport),
	}
	if target.Username != "" || target.Password != "" {
		remoteOpts = append(remoteOpts, remote.WithAuth(&authn.Basic{
			Username: target.Username,
			Password: target.Password,
		}))
	}

	desc, err := remote.Get(ref, remoteOpts...)
	if err != nil {
		return 0, fmt.Errorf("fetching manifest for %s: %w", target.Ref, err)
	}

	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return 0, fmt.Errorf("reading index for %s: %w", target.Ref, err)
		}
		return p.indexSize(idx, 0)
	}

	img, err := desc.Image()
	if err != nil {
		return 0, fmt.Errorf("reading image for %s: %w", target.Ref, err)
	}
	return manifestSize(img)
}

// indexSize returns the size of the platform syft will pull, not the sum:
// syft resolves one platform. Harbor normally fans a scan out to the index's
// children and sends each child digest, so this path is the exception.
//
// When SCANNER_SYFT_IMAGE_PLATFORM matches no child it falls back to the
// largest child. Returning zero there would be a guard bypass, not a safe
// default: the platform is a hint about what syft will choose, and being
// wrong about it must over-estimate, never under-estimate.
//
// A nested index is measured by recursing, never skipped. Treating an
// unmeasurable child as zero was a hole straight through the guard: the largest
// child could be the one that contributes nothing to the total.
func (p *prober) indexSize(idx v1.ImageIndex, depth int) (int64, error) {
	if depth > maxIndexDepth {
		return 0, fmt.Errorf("index nesting deeper than %d levels", maxIndexDepth)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return 0, fmt.Errorf("reading index manifest: %w", err)
	}

	// Two totals in one pass. largestMatching is what the configured platform
	// selects; largestAny is the conservative fallback for when the configured
	// platform selects nothing, which must NOT come out as zero -- that would
	// wave an arbitrarily large artifact straight through the cap.
	var largestMatching, largestAny int64
	matched := false
	// fallbackErr defers a failure on a child the configured platform does not
	// select. Aborting on one would let a broken sibling -- an attestation with
	// a bad digest, a child the registry garbage-collected -- fail the whole
	// probe, and a failed probe runs the scan unguarded. It only matters if the
	// fallback ends up being needed.
	var fallbackErr error

	for _, child := range manifest.Manifests {
		selected := p.platform == "" || child.Platform == nil || platformMatches(p.platform, child.Platform)

		size, err := p.childSize(idx, child, depth)
		if err != nil {
			if selected {
				return 0, err
			}
			if fallbackErr == nil {
				fallbackErr = err
			}
			continue
		}
		if size < 0 {
			continue // not a child syft would pull
		}

		if size > largestAny {
			largestAny = size
		}
		if selected {
			matched = true
			if size > largestMatching {
				largestMatching = size
			}
		}
	}

	if matched {
		return largestMatching, nil
	}
	// Nothing matched the configured platform, so the fallback is load-bearing
	// and every child had to be measurable for it to mean anything.
	if fallbackErr != nil {
		return 0, fallbackErr
	}
	return largestAny, nil
}

// childSize measures one index entry, returning -1 for entries syft would
// never pull (attestations and signatures ride along in the index as non-image
// artifacts).
func (p *prober) childSize(idx v1.ImageIndex, child v1.Descriptor, depth int) (int64, error) {
	switch {
	case child.MediaType.IsIndex():
		nested, err := idx.ImageIndex(child.Digest)
		if err != nil {
			return 0, fmt.Errorf("reading nested index %s: %w", child.Digest, err)
		}
		return p.indexSize(nested, depth+1)
	case child.MediaType.IsImage():
		img, err := idx.Image(child.Digest)
		if err != nil {
			return 0, fmt.Errorf("reading index child %s: %w", child.Digest, err)
		}
		return manifestSize(img)
	default:
		return -1, nil
	}
}

// platformMatches compares an os/arch[/variant] string against an index child.
// A configured platform that matches nothing leaves the caller measuring every
// child, which over-estimates rather than under-estimates.
func platformMatches(configured string, child *v1.Platform) bool {
	parts := strings.Split(configured, "/")
	if len(parts) < 2 {
		return false
	}
	if parts[0] != child.OS || parts[1] != child.Architecture {
		return false
	}
	if len(parts) > 2 && parts[2] != child.Variant {
		return false
	}
	return true
}

// manifestSize sums the layer descriptors. Descriptor sizes come from the
// manifest itself, so no blob is fetched.
func manifestSize(img v1.Image) (int64, error) {
	manifest, err := img.Manifest()
	if err != nil {
		return 0, fmt.Errorf("reading manifest: %w", err)
	}

	total, err := addSize(0, manifest.Config.Size)
	if err != nil {
		return 0, fmt.Errorf("config descriptor: %w", err)
	}
	for i, layer := range manifest.Layers {
		if total, err = addSize(total, layer.Size); err != nil {
			return 0, fmt.Errorf("layer %d descriptor: %w", i, err)
		}
	}
	return total, nil
}

// addSize accumulates a registry-supplied size defensively. A negative
// descriptor would shrink the total and walk an oversized artifact straight past
// the cap; an overflowing one would wrap it negative.
func addSize(total, size int64) (int64, error) {
	if size < 0 {
		return 0, fmt.Errorf("negative size %d", size)
	}
	if size > maxPlausibleSize {
		return 0, fmt.Errorf("implausible size %d", size)
	}
	if total > math.MaxInt64-size {
		return 0, fmt.Errorf("total size overflows int64")
	}
	return total + size, nil
}

// Package imageprobe reads an artifact's manifest to learn how big it is before
// waybill is asked to pull it.
//
// It exists because memory is the binding constraint and nothing else bounds it.
// waybill holds layer content in memory during the pull, so peak RSS runs at
// roughly 4x the compressed size: golang:1.24 (316 MB compressed) peaks at
// 1.32 GiB, and nvidia/cuda:12.6.3-devel (3.7 GB) is still OOM-killed at a 7Gi
// limit. The kill lands on the container, not on the job, so one oversized
// artifact takes every in-flight scan down with it and the pod restarts. A cheap
// manifest read turns that into one typed rejection.
//
// This is a manifest request, not a pull: one GET of a few kilobytes, no blobs.
// That is the whole reason go-containerregistry is acceptable back on the
// runtime path after the switch to waybill's native pull removed it — the thing
// that was expensive was fetching every layer twice, not reading a manifest.
package imageprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
)

// Target is the artifact to measure, with the credentials and transport the pull
// would use. It mirrors waybill.ScanTarget rather than importing it, so the
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
	return fmt.Sprintf(
		"artifact %s is %d compressed bytes, over the %d limit; scanning it needs roughly %d bytes of memory "+
			"(raise SCANNER_WAYBILL_MAX_IMAGE_SIZE and the container memory limit together)",
		e.Ref, e.Size, e.Limit, 4*e.Size)
}

// Prober measures an artifact without pulling it.
type Prober interface {
	// CompressedSize is the total size of the layers waybill would download. For
	// a multi-platform index it is the largest single platform, since waybill
	// pulls one.
	CompressedSize(ctx context.Context, target Target) (int64, error)
}

type prober struct {
	transport http.RoundTripper
}

// New builds a Prober sharing the registry TLS settings the waybill wrapper
// passes on the command line, so the probe and the pull trust the same roots.
func New(cfg etc.Waybill) (Prober, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.InsecureSkipVerify {
		// Operator-selected, WARNed at startup by etc.Check, and the pull that
		// follows runs with --insecure-tls-skip-verify anyway: a probe that
		// verified more strictly than the pull would reject artifacts the scan
		// would then have handled fine.
		tlsConfig.InsecureSkipVerify = true // #nosec G402
	}

	if len(cfg.RegistryCACerts) > 0 {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		for _, path := range cfg.RegistryCACerts {
			pem, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("reading registry CA cert %s: %w", path, err)
			}
			// AppendCertsFromPEM reports whether anything was added. Discarding
			// it turns a malformed bundle into a confusing handshake failure on
			// every scan instead of one startup error.
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("registry CA cert %s contains no usable certificate", path)
			}
		}
		tlsConfig.RootCAs = pool
	}

	base, ok := remote.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("unexpected remote.DefaultTransport type %T", remote.DefaultTransport)
	}
	transport := base.Clone()
	transport.TLSClientConfig = tlsConfig

	return &prober{transport: transport}, nil
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
		return indexSize(desc, remoteOpts)
	}

	img, err := desc.Image()
	if err != nil {
		return 0, fmt.Errorf("reading image for %s: %w", target.Ref, err)
	}
	return manifestSize(img)
}

// indexSize returns the largest platform in an index, not the sum: waybill
// resolves one platform and pulls only that. Harbor normally fans a scan out to
// the index's children and sends each child digest, so this path is the
// exception rather than the rule.
func indexSize(desc *remote.Descriptor, remoteOpts []remote.Option) (int64, error) {
	idx, err := desc.ImageIndex()
	if err != nil {
		return 0, fmt.Errorf("reading index: %w", err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return 0, fmt.Errorf("reading index manifest: %w", err)
	}

	var largest int64
	for _, child := range manifest.Manifests {
		if child.MediaType.IsIndex() {
			continue // nested index: rare, and the children below still cover it
		}
		img, err := idx.Image(child.Digest)
		if err != nil {
			return 0, fmt.Errorf("reading index child %s: %w", child.Digest, err)
		}
		size, err := manifestSize(img)
		if err != nil {
			return 0, err
		}
		if size > largest {
			largest = size
		}
	}
	return largest, nil
}

// manifestSize sums the layer descriptors. Descriptor sizes come from the
// manifest itself, so no blob is fetched.
func manifestSize(img v1.Image) (int64, error) {
	manifest, err := img.Manifest()
	if err != nil {
		return 0, fmt.Errorf("reading manifest: %w", err)
	}
	total := manifest.Config.Size
	for _, layer := range manifest.Layers {
		total += layer.Size
	}
	return total, nil
}

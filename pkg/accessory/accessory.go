// Package accessory fetches an SBOM that Harbor has already generated and
// stored, instead of regenerating one from the image.
//
// Harbor attaches a generated SBOM to its subject image as an OCI referrer, an
// "accessory" in Harbor's vocabulary. Finding it costs one referrers call and
// one blob GET, roughly 40 KB, against an image pull that is frequently
// gigabytes. That is the entire reason this package exists.
//
// Two details about Harbor's accessories are not obvious from the OCI spec and
// are load-bearing here:
//
//  1. The accessory manifest carries no top-level artifactType. Harbor sets the
//     type as the manifest's config.mediaType, and registries synthesize
//     artifactType from config.mediaType when the field is absent (OCI
//     distribution spec, referrers). So the value we filter on shows up in a
//     referrers response even though it appears nowhere in the manifest itself.
//
//  2. The single layer is declared as
//     application/vnd.oci.image.layer.v1.tar but is NOT a tar. It is the raw
//     SBOM JSON document. Untarring it fails; the blob is copied out verbatim.
//
// Both were confirmed against Harbor 2.16 by pulling an accessory and comparing
// it byte for byte with the same SBOM served from Harbor's REST API.
package accessory

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	// HarborSBOMArtifactType is the artifact type Harbor gives a generated SBOM
	// accessory. It is Harbor's own media type, not an SPDX or CycloneDX one:
	// the document format lives inside the blob, and Harbor only ever asks its
	// scanners for application/spdx+json (harbor/src/pkg/scan/sbom/sbom.go).
	HarborSBOMArtifactType = "application/vnd.goharbor.harbor.sbom.v1"

	// annotationCreated is the RFC3339 timestamp Harbor stamps on each accessory
	// manifest. Used to break ties when an image has several.
	annotationCreated = "created"

	// maxSBOMBytes caps what is read out of the accessory blob. A registry can
	// serve an arbitrarily large body regardless of the descriptor size, and
	// this document is parsed and re-encoded in memory. Harbor SBOMs run tens of
	// KB; 64 MiB is several orders of magnitude of headroom and still bounded.
	maxSBOMBytes = 64 << 20
)

// ErrNotFound means the image has no Harbor SBOM accessory. It is the ordinary
// outcome for an image whose project never had SBOM generation enabled, so the
// caller is expected to fall back to generating one rather than fail the scan.
var ErrNotFound = errors.New("no Harbor SBOM accessory found")

// Target identifies the image whose accessory is wanted, plus the credentials
// for the registry. Empty Username and Password means an anonymous pull.
type Target struct {
	// Ref is the fully-qualified image reference, host:port/repository@digest.
	Ref      string
	Username string
	Password string
	// Insecure is true when Harbor's registry URL scheme is http.
	Insecure bool
	// SkipTLSVerify disables certificate verification. Dev and CI only.
	SkipTLSVerify bool
}

// Fetcher looks up a Harbor-generated SBOM for an image.
type Fetcher interface {
	// Fetch returns the SBOM document stored as an accessory of ref. It returns
	// ErrNotFound when the image has none, which is not a failure.
	Fetch(ctx context.Context, target Target) (json.RawMessage, error)
}

type fetcher struct {
	// timeout bounds the whole lookup: referrers call plus blob read. Without it
	// a hung registry would hold a scan worker until the job deadline, having
	// consumed the budget the fallback generation still needs.
	timeout time.Duration
}

func NewFetcher(timeout time.Duration) Fetcher {
	return &fetcher{timeout: timeout}
}

func (f *fetcher) Fetch(ctx context.Context, target Target) (json.RawMessage, error) {
	if f.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.timeout)
		defer cancel()
	}

	var nameOpts []name.Option
	if target.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}
	ref, err := name.ParseReference(target.Ref, nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference: %w", err)
	}

	digestRef, ok := ref.(name.Digest)
	if !ok {
		// Harbor always sends host/repo@sha256:..., and the referrers API is
		// defined on a digest. Resolving a tag here would mean an extra manifest
		// GET for a case that cannot occur.
		return nil, fmt.Errorf("reference is not digest-qualified: %s", target.Ref)
	}

	opts := f.remoteOptions(ctx, target)

	idx, err := remote.Referrers(digestRef, append(opts, remote.WithFilter("artifactType", HarborSBOMArtifactType))...)
	if err != nil {
		// A registry without referrers support answers 404 or 400 here. That is
		// indistinguishable enough from "no accessory" for the caller's purposes:
		// either way there is nothing to reuse.
		slog.Warn("Referrers lookup failed; falling back to generating",
			slog.String("image_ref", target.Ref), slog.String("err", err.Error()))
		return nil, ErrNotFound
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("reading referrers index: %w", err)
	}

	desc := newestSBOM(manifest.Manifests)
	if desc == nil {
		// Log what the registry actually returned. "No accessory" and "the
		// accessory is there but not shaped the way this code expects" look
		// identical from the outside, and the second one silently costs a full
		// image pull on every scan.
		types := make([]string, 0, len(manifest.Manifests))
		for _, m := range manifest.Manifests {
			types = append(types, m.ArtifactType)
		}
		slog.Debug("Referrers returned no Harbor SBOM",
			slog.String("image_ref", target.Ref),
			slog.Int("referrer_count", len(manifest.Manifests)),
			slog.String("artifact_types", strings.Join(types, ",")))
		return nil, ErrNotFound
	}

	slog.Debug("Found Harbor SBOM accessory",
		slog.String("image_ref", target.Ref),
		slog.String("accessory_digest", desc.Digest.String()))

	return readSBOMBlob(digestRef.Context().Digest(desc.Digest.String()), opts)
}

// newestSBOM picks the most recently created SBOM accessory from a referrers
// index, or nil when there is none.
//
// The artifactType filter is re-applied client-side on purpose. A registry is
// permitted to ignore the filter parameter entirely and return every referrer,
// and it signals whether it honoured it via OCI-Filters-Applied, which
// go-containerregistry does not surface. Trusting the server here would hand a
// cosign signature or an in-toto attestation to the SBOM parser.
func newestSBOM(descs []v1.Descriptor) *v1.Descriptor {
	var newest *v1.Descriptor
	var newestAt time.Time
	for i := range descs {
		desc := &descs[i]
		if desc.ArtifactType != HarborSBOMArtifactType {
			continue
		}
		// A missing or malformed timestamp parses to the zero time, which loses
		// every comparison against a well-formed one. That is the right
		// preference order, and it still lets an untimestamped accessory win
		// when it is the only candidate.
		created, _ := time.Parse(time.RFC3339, desc.Annotations[annotationCreated])
		if newest == nil || created.After(newestAt) {
			newest, newestAt = desc, created
		}
	}
	return newest
}

// readSBOMBlob pulls the accessory manifest and copies its single layer out.
//
// The layer is the SBOM document verbatim despite its tar media type (see the
// package comment), so this deliberately does not go through a tar reader.
func readSBOMBlob(ref name.Digest, opts []remote.Option) (json.RawMessage, error) {
	img, err := remote.Image(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("fetching accessory manifest: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("reading accessory layers: %w", err)
	}
	if len(layers) != 1 {
		return nil, fmt.Errorf("accessory has %d layers, want exactly 1", len(layers))
	}

	// Uncompressed, not Compressed: the media type has no compression suffix, so
	// these return the same bytes today, but Uncompressed keeps working if
	// Harbor ever starts gzipping the layer.
	rc, err := layers[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("opening accessory layer: %w", err)
	}
	defer func() { _ = rc.Close() }()

	// LimitReader is set one byte past the cap so a document that is exactly at
	// the limit is accepted and one byte over is still detected.
	data, err := io.ReadAll(io.LimitReader(rc, maxSBOMBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading accessory layer: %w", err)
	}
	if len(data) > maxSBOMBytes {
		return nil, fmt.Errorf("accessory SBOM exceeds %d bytes", maxSBOMBytes)
	}

	// Validate before returning: the blob is about to be handed to a converter
	// and then stored as a pre-marshaled report field, and a non-JSON body would
	// otherwise surface far from its cause.
	if !json.Valid(data) {
		return nil, errors.New("accessory SBOM is not valid JSON")
	}
	return json.RawMessage(data), nil
}

func (f *fetcher) remoteOptions(ctx context.Context, target Target) []remote.Option {
	auth := authn.Anonymous
	if target.Username != "" || target.Password != "" {
		auth = &authn.Basic{Username: target.Username, Password: target.Password}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if target.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in, dev/CI only
	}

	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuth(auth),
		remote.WithTransport(transport),
	}
}

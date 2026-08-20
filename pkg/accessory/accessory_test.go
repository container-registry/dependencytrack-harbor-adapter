package accessory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const spdxDoc = `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","packages":[{"name":"musl"}]}`

// newRegistry starts a real in-memory OCI registry. The fast path depends on
// registry behavior (referrers, artifactType synthesis from config.mediaType),
// so a hand-rolled HTTP fake would be asserting against a fiction.
func newRegistry(t *testing.T) (host string, repo name.Repository) {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	repo, err = name.NewRepository(u.Host + "/library/app")
	require.NoError(t, err)
	return u.Host, repo
}

// pushSubject writes a plain image and returns its digest reference.
func pushSubject(t *testing.T, repo name.Repository) name.Digest {
	t.Helper()
	img, err := random.Image(256, 1)
	require.NoError(t, err)
	digest, err := img.Digest()
	require.NoError(t, err)

	ref := repo.Digest(digest.String())
	require.NoError(t, remote.Write(ref, img))
	return ref
}

// pushAccessory reproduces how Harbor stores a generated SBOM: one layer holding
// the raw document (declared as a tar media type it is not), the Harbor SBOM
// media type as the manifest CONFIG media type and no top-level artifactType,
// and a subject pointing at the image.
func pushAccessory(t *testing.T, subject name.Digest, doc, created string) name.Digest {
	t.Helper()

	layer := static.NewLayer([]byte(doc), types.MediaType("application/vnd.oci.image.layer.v1.tar"))
	acc, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)
	acc = mutate.ConfigMediaType(acc, types.MediaType(HarborSBOMArtifactType))
	acc = mutate.MediaType(acc, types.OCIManifestSchema1)
	acc = mutate.Annotations(acc, map[string]string{annotationCreated: created}).(v1.Image)

	subjDesc, err := partialDescriptor(subject)
	require.NoError(t, err)
	acc = mutate.Subject(acc, *subjDesc).(v1.Image)

	digest, err := acc.Digest()
	require.NoError(t, err)
	ref := subject.Context().Digest(digest.String())
	require.NoError(t, remote.Write(ref, acc))
	return ref
}

func partialDescriptor(ref name.Digest) (*v1.Descriptor, error) {
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, err
	}
	return &v1.Descriptor{MediaType: desc.MediaType, Size: desc.Size, Digest: desc.Digest}, nil
}

func targetFor(ref name.Digest) Target {
	return Target{Ref: ref.String(), Insecure: true}
}

// The load-bearing case: Harbor's accessory blob is the SBOM verbatim, despite
// the tar media type. If this ever goes through a tar reader it breaks.
func TestFetchReturnsTheAccessoryBlobVerbatim(t *testing.T) {
	_, repo := newRegistry(t)
	subject := pushSubject(t, repo)
	pushAccessory(t, subject, spdxDoc, "2026-08-20T15:31:07Z")

	got, err := NewFetcher(10*time.Second).Fetch(context.Background(), targetFor(subject))
	require.NoError(t, err)
	assert.JSONEq(t, spdxDoc, string(got))
}

// An image with no accessory is the ordinary case for a project that never had
// SBOM generation enabled. It must be a sentinel the caller can branch on, not a
// scan failure.
func TestFetchReturnsNotFoundWithoutAnAccessory(t *testing.T) {
	_, repo := newRegistry(t)
	subject := pushSubject(t, repo)

	_, err := NewFetcher(10*time.Second).Fetch(context.Background(), targetFor(subject))
	assert.ErrorIs(t, err, ErrNotFound)
}

// Harbor pushes a new accessory each time SBOM generation runs, so an image can
// carry several and picking an arbitrary one serves a stale inventory for the
// same digest.
//
// This exercises newestSBOM directly rather than through a registry. The
// in-memory test registry has no /referrers endpoint, so go-containerregistry
// falls back to the tag-based scheme, and that fallback drops the per-descriptor
// annotations this selection is based on. Harbor implements the real endpoint
// and does return them (verified against Harbor 2.16, which answers with
// OCI-Filters-Applied: artifactType and a "created" annotation per referrer), so
// driving this through the fake would be testing the wrong shape of data.
func TestNewestSBOMPicksTheMostRecentlyCreated(t *testing.T) {
	descs := []v1.Descriptor{
		{ArtifactType: "application/vnd.dev.cosign.artifact.sig.v1+json", Digest: digestFor("sig")},
		{
			ArtifactType: HarborSBOMArtifactType,
			Digest:       digestFor("old"),
			Annotations:  map[string]string{annotationCreated: "2026-01-01T00:00:00Z"},
		},
		{
			ArtifactType: HarborSBOMArtifactType,
			Digest:       digestFor("current"),
			Annotations:  map[string]string{annotationCreated: "2026-08-20T15:31:07Z"},
		},
	}

	got := newestSBOM(descs)
	require.NotNil(t, got)
	assert.Equal(t, digestFor("current"), got.Digest)
}

// A descriptor with no parsable timestamp must still be usable when it is the
// only candidate, rather than being discarded for a missing annotation.
func TestNewestSBOMAcceptsAnUntimestampedSoleCandidate(t *testing.T) {
	got := newestSBOM([]v1.Descriptor{{ArtifactType: HarborSBOMArtifactType, Digest: digestFor("only")}})
	require.NotNil(t, got)
	assert.Equal(t, digestFor("only"), got.Digest)
}

// A well-formed timestamp must beat a missing one regardless of position, so a
// legacy accessory without annotations cannot shadow a current one.
func TestNewestSBOMPrefersATimestampedAccessory(t *testing.T) {
	got := newestSBOM([]v1.Descriptor{
		{ArtifactType: HarborSBOMArtifactType, Digest: digestFor("untimestamped")},
		{
			ArtifactType: HarborSBOMArtifactType,
			Digest:       digestFor("timestamped"),
			Annotations:  map[string]string{annotationCreated: "2026-08-20T15:31:07Z"},
		},
	})
	require.NotNil(t, got)
	assert.Equal(t, digestFor("timestamped"), got.Digest)
}

func TestNewestSBOMReturnsNilWithoutACandidate(t *testing.T) {
	assert.Nil(t, newestSBOM(nil))
	assert.Nil(t, newestSBOM([]v1.Descriptor{{ArtifactType: "application/vnd.in-toto+json"}}))
}

// digestFor builds a distinct, well-formed digest from a label so failures name
// the accessory rather than a hash prefix.
func digestFor(label string) v1.Hash {
	sum := sha256.Sum256([]byte(label))
	return v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(sum[:])}
}

// A registry may ignore the artifactType filter and return every referrer. The
// client-side filter is what stops a cosign signature or an in-toto attestation
// being handed to the SBOM parser as if it were a document.
func TestFetchIgnoresNonSBOMReferrers(t *testing.T) {
	_, repo := newRegistry(t)
	subject := pushSubject(t, repo)

	// A signature-shaped referrer with a different config media type.
	sig, err := mutate.AppendLayers(empty.Image,
		static.NewLayer([]byte(`{"critical":{}}`), types.MediaType("application/vnd.dev.cosign.simplesigning.v1+json")))
	require.NoError(t, err)
	sig = mutate.ConfigMediaType(sig, "application/vnd.dev.cosign.artifact.sig.v1+json")
	sig = mutate.MediaType(sig, types.OCIManifestSchema1)
	subjDesc, err := partialDescriptor(subject)
	require.NoError(t, err)
	sig = mutate.Subject(sig, *subjDesc).(v1.Image)
	sigDigest, err := sig.Digest()
	require.NoError(t, err)
	require.NoError(t, remote.Write(subject.Context().Digest(sigDigest.String()), sig))

	_, err = NewFetcher(10*time.Second).Fetch(context.Background(), targetFor(subject))
	assert.ErrorIs(t, err, ErrNotFound, "a signature must not be mistaken for an SBOM")
}

// A registry with no referrers support answers 404 here. That is "nothing to
// reuse", not a broken scan, so the caller can fall back to generating.
func TestFetchTreatsAMissingReferrersAPIAsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/referrers/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	_, err = NewFetcher(5*time.Second).Fetch(context.Background(), Target{
		Ref:      fmt.Sprintf("%s/library/app@sha256:%064d", u.Host, 1),
		Insecure: true,
	})
	assert.ErrorIs(t, err, ErrNotFound)
}

// The referrers API is defined on a digest, and Harbor always sends one. A tag
// must be refused rather than silently resolved with an extra manifest GET.
func TestFetchRejectsANonDigestReference(t *testing.T) {
	_, err := NewFetcher(time.Second).Fetch(context.Background(), Target{Ref: "example.com/library/app:latest"})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound)
	assert.Contains(t, err.Error(), "digest")
}

// The blob is about to be converted and then stored as a pre-marshaled report
// field. A non-JSON body has to fail here, where the cause is still visible.
func TestFetchRejectsANonJSONBlob(t *testing.T) {
	_, repo := newRegistry(t)
	subject := pushSubject(t, repo)
	pushAccessory(t, subject, "this is not json", "2026-08-20T15:31:07Z")

	_, err := NewFetcher(10*time.Second).Fetch(context.Background(), targetFor(subject))
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound)
	assert.Contains(t, err.Error(), "valid JSON")
}

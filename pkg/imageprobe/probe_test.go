package imageprobe

import (
	"context"
	"io"
	"log"
	"math"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
)

// testRegistry serves a real OCI registry over plain HTTP, so the probe is
// exercised against actual manifest documents rather than a hand-rolled fake.
func testRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(nopLogger(t))))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return u.Host
}

func nopLogger(_ *testing.T) *log.Logger { return log.New(io.Discard, "", 0) }

func push(t *testing.T, host, repo string, taggable remote.Taggable) string {
	t.Helper()
	ref, err := name.NewTag(host+"/"+repo+":latest", name.Insecure)
	require.NoError(t, err)
	switch v := taggable.(type) {
	case v1.Image:
		require.NoError(t, remote.Write(ref, v))
	case v1.ImageIndex:
		require.NoError(t, remote.WriteIndex(ref, v))
	default:
		t.Fatalf("unsupported taggable %T", taggable)
	}
	return ref.String()
}

func newProber(t *testing.T, platform string) Prober {
	t.Helper()
	p, err := New(etc.Waybill{ImagePlatform: platform})
	require.NoError(t, err)
	return p
}

func TestCompressedSizeSumsLayers(t *testing.T) {
	host := testRegistry(t)
	img, err := random.Image(1024, 3)
	require.NoError(t, err)
	ref := push(t, host, "single", img)

	got, err := newProber(t, "").CompressedSize(context.Background(), Target{Ref: ref, Insecure: true})
	require.NoError(t, err)

	want, err := manifestSize(img)
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Positive(t, got)
}

// TestNestedIndexIsMeasuredNotSkipped is the regression pin for a hole straight
// through the guard: a nested index used to be skipped, contributing zero, so
// the largest child could be the one that counted for nothing and an oversized
// artifact walked past the cap.
func TestNestedIndexIsMeasuredNotSkipped(t *testing.T) {
	host := testRegistry(t)

	small, err := random.Image(64, 1)
	require.NoError(t, err)
	big, err := random.Image(4096, 5)
	require.NoError(t, err)

	// The big image lives inside a nested index; only the small one is a direct
	// child. A skipping probe reports the small size.
	inner := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: big})
	outer := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: small},
		mutate.IndexAddendum{Add: inner},
	)
	ref := push(t, host, "nested", outer)

	got, err := newProber(t, "").CompressedSize(context.Background(), Target{Ref: ref, Insecure: true})
	require.NoError(t, err)

	bigSize, err := manifestSize(big)
	require.NoError(t, err)
	smallSize, err := manifestSize(small)
	require.NoError(t, err)
	require.Greater(t, bigSize, smallSize, "fixture must have a clearly larger nested image")

	assert.Equal(t, bigSize, got, "the nested index must be measured, not treated as zero")
}

// TestIndexChargesTheConfiguredPlatform pins that the probe measures what
// waybill will actually pull. Charging the largest child regardless would refuse
// a scan whose selected platform sits comfortably under the cap.
func TestIndexChargesTheConfiguredPlatform(t *testing.T) {
	host := testRegistry(t)

	smallArm, err := random.Image(64, 1)
	require.NoError(t, err)
	bigAmd, err := random.Image(4096, 5)
	require.NoError(t, err)

	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: smallArm, Descriptor: v1.Descriptor{
			Platform: &v1.Platform{OS: "linux", Architecture: "arm64"},
		}},
		mutate.IndexAddendum{Add: bigAmd, Descriptor: v1.Descriptor{
			Platform: &v1.Platform{OS: "linux", Architecture: "amd64"},
		}},
	)
	ref := push(t, host, "multiarch", idx)

	armSize, err := manifestSize(smallArm)
	require.NoError(t, err)
	amdSize, err := manifestSize(bigAmd)
	require.NoError(t, err)
	require.Greater(t, amdSize, armSize)

	got, err := newProber(t, "linux/arm64").CompressedSize(context.Background(), Target{Ref: ref, Insecure: true})
	require.NoError(t, err)
	assert.Equal(t, armSize, got, "a configured platform must be charged, not the largest child")

	// With no platform configured the largest child is the safe estimate.
	got, err = newProber(t, "").CompressedSize(context.Background(), Target{Ref: ref, Insecure: true})
	require.NoError(t, err)
	assert.Equal(t, amdSize, got)
}

// TestAddSizeRejectsHostileDescriptors: sizes come from a document the remote
// controls, and a negative one would shrink the total enough to walk an
// oversized artifact past the cap.
func TestAddSizeRejectsHostileDescriptors(t *testing.T) {
	tests := []struct {
		name        string
		total, size int64
		wantErr     string
	}{
		{"negative descriptor", 100, -1 << 40, "negative size"},
		{"implausible descriptor", 0, maxPlausibleSize + 1, "implausible size"},
		{"overflowing total", math.MaxInt64 - 10, 11, "overflows int64"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := addSize(tc.total, tc.size)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}

	got, err := addSize(100, 20)
	require.NoError(t, err)
	assert.Equal(t, int64(120), got)
}

func TestPlatformMatches(t *testing.T) {
	linuxArm := &v1.Platform{OS: "linux", Architecture: "arm64"}
	withVariant := &v1.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}

	assert.True(t, platformMatches("linux/arm64", linuxArm))
	assert.False(t, platformMatches("linux/amd64", linuxArm))
	assert.False(t, platformMatches("windows/arm64", linuxArm))
	assert.True(t, platformMatches("linux/arm/v7", withVariant))
	assert.False(t, platformMatches("linux/arm/v6", withVariant))
	assert.False(t, platformMatches("linux", linuxArm), "a malformed platform must not match everything")
}

// TestUnmatchedPlatformFallsBackToLargest is the regression pin for a guard
// bypass: skipping every non-matching child left the total at zero when the
// configured platform matched nothing, so an arbitrarily large artifact was
// reported as 0 bytes and sailed through the cap.
func TestUnmatchedPlatformFallsBackToLargest(t *testing.T) {
	host := testRegistry(t)
	big, err := random.Image(4096, 5)
	require.NoError(t, err)
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: big, Descriptor: v1.Descriptor{
		Platform: &v1.Platform{OS: "linux", Architecture: "amd64"},
	}})
	ref := push(t, host, "nomatch", idx)

	got, err := newProber(t, "linux/s390x").CompressedSize(context.Background(), Target{Ref: ref, Insecure: true})
	require.NoError(t, err)

	want, err := manifestSize(big)
	require.NoError(t, err)
	assert.Equal(t, want, got, "an unmatched platform must over-estimate, never report zero")
}

// TestEstimatedMemorySaturates: the estimate feeds operator guidance in the
// rejection message, and a wrapped negative there is worse than no number.
func TestEstimatedMemorySaturates(t *testing.T) {
	assert.Equal(t, int64(470), EstimatedMemory(100))
	assert.Equal(t, int64(0), EstimatedMemory(0))
	assert.Equal(t, int64(0), EstimatedMemory(-5))
	assert.Equal(t, int64(math.MaxInt64), EstimatedMemory(math.MaxInt64))
	assert.Positive(t, EstimatedMemory(math.MaxInt64/2), "must never wrap negative")
}

func TestMissingArtifactIsAnError(t *testing.T) {
	host := testRegistry(t)
	_, err := newProber(t, "").CompressedSize(context.Background(), Target{
		Ref: host + "/nope@sha256:" + "0000000000000000000000000000000000000000000000000000000000000000", Insecure: true,
	})
	require.Error(t, err)
}

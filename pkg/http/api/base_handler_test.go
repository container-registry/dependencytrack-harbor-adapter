package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExactMimeStrings pins the exact contract MIME strings, including the
// version parameter on the SBOM report type.
func TestExactMimeStrings(t *testing.T) {
	assert.Equal(t, "application/vnd.security.sbom.report+json; version=1.0", MimeTypeSecuritySBOMReport.String())
	assert.Equal(t, "application/vnd.scanner.adapter.metadata+json; version=1.0", MimeTypeMetadata.String())
	assert.Equal(t, "application/vnd.scanner.adapter.scan.response+json; version=1.0", MimeTypeScanResponse.String())
	assert.Equal(t, "application/vnd.docker.distribution.manifest.v2+json", MimeTypeDockerImageManifestV2.String())
	assert.Equal(t, "application/vnd.oci.image.manifest.v1+json", MimeTypeOCIImageManifest.String())
	assert.Equal(t, MediaType("application/spdx+json"), MediaTypeSPDX)
}

func TestMIMETypeParse(t *testing.T) {
	t.Run("sbom report with version param", func(t *testing.T) {
		var mt MIMEType
		require.NoError(t, mt.Parse("application/vnd.security.sbom.report+json; version=1.0"))
		assert.True(t, mt.Equal(MimeTypeSecuritySBOMReport))
	})
	t.Run("sbom report without params", func(t *testing.T) {
		var mt MIMEType
		require.NoError(t, mt.Parse("application/vnd.security.sbom.report+json"))
		assert.True(t, mt.Equal(MimeTypeSecuritySBOMReport))
	})
	t.Run("vulnerability report rejected (sbom-only adapter)", func(t *testing.T) {
		var mt MIMEType
		require.Error(t, mt.Parse("application/vnd.security.vulnerability.report; version=1.1"))
	})
}

// TestMIMETypeParseAcceptsLegalSpellings pins that a client is not punished for
// formatting a header the way RFC 9110 allows. The old exact-string switch only
// matched this adapter's own rendering, so a missing space after ";" -- which
// plenty of clients emit -- produced a 415 for a valid request.
func TestMIMETypeParseAcceptsLegalSpellings(t *testing.T) {
	for _, value := range []string{
		"application/vnd.security.sbom.report+json; version=1.0",
		"application/vnd.security.sbom.report+json;version=1.0",
		"application/vnd.security.sbom.report+json;  version=1.0",
		"  application/vnd.security.sbom.report+json ; version=1.0  ",
		"APPLICATION/VND.SECURITY.SBOM.REPORT+JSON; VERSION=1.0",
		"application/vnd.security.sbom.report+json",
	} {
		t.Run(value, func(t *testing.T) {
			var mt MIMEType
			require.NoError(t, mt.Parse(value))
			assert.Equal(t, MimeTypeSecuritySBOMReport.Subtype, mt.Subtype)
		})
	}
}

func TestMIMETypeParseRejectsOthers(t *testing.T) {
	for _, value := range []string{
		"application/vnd.cyclonedx+json",
		"application/vnd.security.sbom.report+json; version=2.0",
		"not a media type at all ///",
		"",
	} {
		t.Run(value, func(t *testing.T) {
			var mt MIMEType
			assert.Error(t, mt.Parse(value))
		})
	}
}

// TestClientAcceptsGzipHonorsQValues: "gzip;q=0" is the explicit way to refuse
// an encoding, and a substring match read it as acceptance -- so a client that
// said it could not decompress received a compressed report.
func TestClientAcceptsGzipHonorsQValues(t *testing.T) {
	tests := []struct {
		header string
		want   bool
	}{
		{"gzip", true},
		{"gzip, deflate", true},
		{"gzip;q=1.0", true},
		{"gzip;q=0.5", true},
		{"gzip;q=0", false},
		{"gzip;q=0.0", false},
		{"deflate, gzip;q=0", false},
		{"*", true},
		{"*;q=0", false},
		{"*, gzip;q=0", false},
		{"identity", false},
		{"", false},
		{"GZIP", true},
	}
	for _, tc := range tests {
		t.Run(tc.header, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set(HeaderAcceptEncoding, tc.header)
			}
			assert.Equal(t, tc.want, clientAcceptsGzip(req))
		})
	}
}

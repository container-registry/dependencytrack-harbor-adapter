package api

import (
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

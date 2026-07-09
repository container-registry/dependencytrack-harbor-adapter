package harbor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetImageRef(t *testing.T) {
	cases := []struct {
		name         string
		url          string
		wantRef      string
		wantInsecure bool
	}{
		{"https default port", "https://core.harbor.domain", "core.harbor.domain:443/library/alpine@sha256:abc", false},
		{"http default port derives insecure", "http://core:8080", "core:8080/library/alpine@sha256:abc", true},
		{"https explicit port", "https://reg.example.com:5443", "reg.example.com:5443/library/alpine@sha256:abc", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := ScanRequest{
				Registry: Registry{URL: tc.url},
				Artifact: Artifact{Repository: "library/alpine", Digest: "sha256:abc"},
			}
			ref, insecure, err := req.GetImageRef()
			require.NoError(t, err)
			assert.Equal(t, tc.wantRef, ref)
			assert.Equal(t, tc.wantInsecure, insecure)
		})
	}
}

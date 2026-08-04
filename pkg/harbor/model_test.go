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
		{"http default port derives insecure", "http://core.harbor.domain", "core.harbor.domain:80/library/alpine@sha256:abc", true},
		{"http explicit port derives insecure", "http://core:8080", "core:8080/library/alpine@sha256:abc", true},
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

// TestGetImageRefBracketsIPv6 pins that an IPv6 registry produces a parseable
// reference. url.Hostname() strips the brackets, and "::1:443/repo@sha256:..."
// is not a reference any registry client will accept.
func TestGetImageRefBracketsIPv6(t *testing.T) {
	req := ScanRequest{
		Registry: Registry{URL: "http://[::1]:8080"},
		Artifact: Artifact{Repository: "library/alpine", Digest: "sha256:deadbeef"},
	}
	ref, insecure, err := req.GetImageRef()
	require.NoError(t, err)
	assert.Equal(t, "[::1]:8080/library/alpine@sha256:deadbeef", ref)
	assert.True(t, insecure)
}

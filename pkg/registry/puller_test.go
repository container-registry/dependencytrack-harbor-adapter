package registry

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pushRandomImage stands up an in-memory registry (optionally behind Basic auth),
// pushes a random image, and returns the digest reference host:port/repo@digest.
func pushRandomImage(t *testing.T, wantUser, wantPass string) (host, ref string, srv *httptest.Server) {
	t.Helper()
	reg := ggcrregistry.New()

	handler := reg
	if wantUser != "" {
		handler = basicAuthMiddleware(reg, wantUser, wantPass)
	}
	srv = httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	host = u.Host

	img, err := random.Image(1024, 2)
	require.NoError(t, err)

	repo := host + "/test/repo:latest"
	pushOpts := []crane.Option{crane.Insecure}
	if wantUser != "" {
		pushOpts = append(pushOpts, crane.WithAuth(&authn.Basic{Username: wantUser, Password: wantPass}))
	}
	require.NoError(t, crane.Push(img, repo, pushOpts...))

	dig, err := img.Digest()
	require.NoError(t, err)
	ref = host + "/test/repo@" + dig.String()
	return host, ref, srv
}

func TestPullToTarball_Anonymous(t *testing.T) {
	_, ref, _ := pushRandomImage(t, "", "")

	dest := filepath.Join(t.TempDir(), "image.tar")
	err := NewPuller().PullToTarball(context.Background(), ImageRef{
		Name:      ref,
		Anonymous: true,
		Insecure:  true,
	}, dest)
	require.NoError(t, err)
	assertDockerSaveTarball(t, dest)
}

func TestPullToTarball_Basic(t *testing.T) {
	_, ref, _ := pushRandomImage(t, "robot$scan", "s3cr3t:with:colons")

	dest := filepath.Join(t.TempDir(), "image.tar")
	err := NewPuller().PullToTarball(context.Background(), ImageRef{
		Name:     ref,
		Username: "robot$scan",
		Password: "s3cr3t:with:colons",
		Insecure: true,
	}, dest)
	require.NoError(t, err)
	assertDockerSaveTarball(t, dest)
}

func TestPullToTarball_BadAuthFails(t *testing.T) {
	_, ref, _ := pushRandomImage(t, "robot$scan", "correct")

	dest := filepath.Join(t.TempDir(), "image.tar")
	err := NewPuller().PullToTarball(context.Background(), ImageRef{
		Name:     ref,
		Username: "robot$scan",
		Password: "wrong",
		Insecure: true,
	}, dest)
	require.Error(t, err)
}

// assertDockerSaveTarball verifies the output is a docker-save (v1) tarball,
// i.e. it contains a manifest.json entry, which is what mikebom's --image accepts.
func assertDockerSaveTarball(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	tr := tar.NewReader(f)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if hdr.Name == "manifest.json" {
			found = true
		}
	}
	assert.True(t, found, "tarball must contain manifest.json (docker-save format)")
}

func basicAuthMiddleware(next http.Handler, user, pass string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
		if !strings.EqualFold(auth, want) {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

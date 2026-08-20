package dtrack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, h http.HandlerFunc) (Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewClient(Config{BaseURL: srv.URL, APIKey: "odt_test", Timeout: 5 * time.Second}), srv
}

// The BOM travels base64-encoded inside a JSON field. Getting that wrong is
// silent: Dependency-Track answers 400 with a schema-validation problem document
// that says nothing about the encoding, so the round-trip is asserted here.
func TestUploadEncodesTheBOMAndSetsAutoCreate(t *testing.T) {
	var got bomSubmitRequest
	var apiKey, method, path string

	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		apiKey, method, path = r.Header.Get("X-Api-Key"), r.Method, r.URL.Path
		body, _ := io.ReadAll(r.Body)
		require.NoError(t, json.Unmarshal(body, &got))
		_, _ = w.Write([]byte(`{"token":"tok-1"}`))
	})

	bom := json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	err := client.Upload(context.Background(), UploadRequest{
		ProjectName:    "library/alpine",
		ProjectVersion: "sha256:deadbeef",
		ProjectTags:    []string{"harbor"},
		ParentName:     "library",
		IsLatest:       true,
		CycloneDX:      bom,
	})
	require.NoError(t, err)

	assert.Equal(t, http.MethodPut, method)
	assert.Equal(t, "/api/v1/bom", path)
	assert.Equal(t, "odt_test", apiKey)
	assert.Equal(t, "library/alpine", got.ProjectName)
	assert.Equal(t, "sha256:deadbeef", got.ProjectVersion)
	assert.Equal(t, "library", got.ParentName)
	assert.Equal(t, []string{"harbor"}, got.ProjectTags)
	assert.True(t, got.IsLatest)

	// autoCreate must be on: the adapter is the first thing that ever mentions
	// this project to Dependency-Track, so without it every upload 404s.
	assert.True(t, got.AutoCreate, "autoCreate must be set or the first upload for a repository fails")

	decoded, err := base64.StdEncoding.DecodeString(got.BOM)
	require.NoError(t, err, "bom field must be base64")
	assert.JSONEq(t, string(bom), string(decoded))
}

// A rejected BOM must surface Dependency-Track's own explanation. The response
// body is the RFC 9457 problem document naming the schema violation, and without
// it the operator sees only "400" against a document they cannot inspect.
func TestUploadSurfacesTheRejectionReason(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"title":"The uploaded BOM is invalid","detail":"$.specVersion: does not have a value in the enumeration"}`))
	})

	err := client.Upload(context.Background(), UploadRequest{
		ProjectName: "p", ProjectVersion: "v",
		CycloneDX: json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
	assert.Contains(t, err.Error(), "does not have a value in the enumeration")
}

// The token is informational. An upload that Dependency-Track accepted must not
// be reported as failed just because the body was not the shape expected.
func TestUploadSucceedsWithoutAParseableToken(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	})

	err := client.Upload(context.Background(), UploadRequest{
		ProjectName: "p", ProjectVersion: "v",
		CycloneDX: json.RawMessage(`{}`),
	})
	assert.NoError(t, err)
}

// Ping has to fail on a bad key, not merely on an unreachable host. An
// unauthenticated endpoint would let a deployment with a typo'd or
// under-privileged API key start up healthy and only fail on the first scan.
func TestPingRejectsABadAPIKey(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"name":"adapter"}`))
	})

	err := client.Ping(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestPingUsesAnAuthenticatedEndpoint(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := NewClient(Config{BaseURL: srv.URL, APIKey: "k", Timeout: time.Second})
	require.NoError(t, client.Ping(context.Background()))
	assert.Equal(t, "/api/v1/team/self", path,
		"/api/version is unauthenticated and would pass with any key")
}

// A trailing slash on the configured URL must not produce "//api/v1/bom".
func TestBaseURLTrailingSlashIsNormalized(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := NewClient(Config{BaseURL: srv.URL + "/", APIKey: "k", Timeout: time.Second})
	require.NoError(t, client.Ping(context.Background()))
	assert.Equal(t, "/api/v1/team/self", path)
}

// autoCreate creates the project but not its parent, so an upload naming a
// parent that does not exist is rejected outright. Losing the whole inventory
// over a presentational detail is the wrong trade, and widening the API key to
// PORTFOLIO_MANAGEMENT_CREATE just to create a folder is worse.
func TestUploadRetriesWithoutAMissingParent(t *testing.T) {
	var bodies []bomSubmitRequest

	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var req bomSubmitRequest
		body, _ := io.ReadAll(r.Body)
		require.NoError(t, json.Unmarshal(body, &req))
		bodies = append(bodies, req)

		if req.ParentName != "" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("The parent project could not be found."))
			return
		}
		_, _ = w.Write([]byte(`{"token":"tok-2"}`))
	})

	err := client.Upload(context.Background(), UploadRequest{
		ProjectName: "library/alpine", ProjectVersion: "sha256:deadbeef",
		ParentName: "library", CycloneDX: json.RawMessage(`{}`),
	})
	require.NoError(t, err, "a missing parent must not lose the BOM")

	require.Len(t, bodies, 2, "expected one attempt with the parent and one without")
	assert.Equal(t, "library", bodies[0].ParentName)
	assert.Empty(t, bodies[1].ParentName)
	assert.Equal(t, "library/alpine", bodies[1].ProjectName, "the retry must carry the same project")
}

// Only the missing-parent 404 is recoverable. Retrying a schema rejection would
// send the same invalid document twice and report a failure with the wrong cause.
func TestUploadDoesNotRetryOtherFailures(t *testing.T) {
	attempts := 0
	client, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"$.specVersion: does not have a value in the enumeration"}`))
	})

	err := client.Upload(context.Background(), UploadRequest{
		ProjectName: "p", ProjectVersion: "v", ParentName: "parent",
		CycloneDX: json.RawMessage(`{}`),
	})
	require.Error(t, err)
	assert.Equal(t, 1, attempts, "a schema rejection must not be retried")
}

// Without a parent there is nothing to fall back to, so a 404 is just a failure.
func TestUploadWithoutAParentDoesNotRetry(t *testing.T) {
	attempts := 0
	client, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("The parent project could not be found."))
	})

	err := client.Upload(context.Background(), UploadRequest{
		ProjectName: "p", ProjectVersion: "v", CycloneDX: json.RawMessage(`{}`),
	})
	require.Error(t, err)
	assert.Equal(t, 1, attempts)
}

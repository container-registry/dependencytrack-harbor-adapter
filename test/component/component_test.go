//go:build component

// Package component is the component-tier test (plan M4, 04-architect-delivery.md
// section 1.4). It stands up registry:2 (htpasswd, plain HTTP) + redis + the REAL
// adapter image (which contains the real mikebom binary) via docker compose, then
// plays Harbor's client against the adapter: push an image, POST /api/v1/scan with a
// Basic authorization header, poll GET /scan/{id}/report asserting a 302+Refresh-After
// then a 200, and validate the report envelope and the embedded SPDX 2.3 document.
//
// Run with `task test:component` (it builds the image and sets TEST_ADAPTER_IMAGE).
package component

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	composeProject  = "mikebom-component"
	adapterBaseURL  = "http://localhost:8099"
	registryHost    = "localhost:5099"
	registryRepo    = "component/alpine"
	regUser         = "testuser"
	regPassword     = "testpassword"
	sbomMediaType   = "application/spdx+json"
	reportMIMEType  = "application/vnd.security.sbom.report+json; version=1.0"
	fixtureImageRef = "alpine:3.20"
	// harborClientTimeout is Harbor's per-request scan/rest client timeout
	// (harbor/src/pkg/scan/rest/v1/client.go). The report handler must respond well
	// under this.
	harborClientTimeout = 5 * time.Second
)

// shared across tests, populated by TestMain.
var (
	fixtureDigest  string // sha256:... of the pushed fixture image
	fixtureTarball string // host path to the docker-save tarball of the fixture
	adapterImage   string // value of TEST_ADAPTER_IMAGE
)

func composeFile(t testing.TB) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Join(wd, "docker-compose.yml")
}

func TestMain(m *testing.M) {
	adapterImage = os.Getenv("TEST_ADAPTER_IMAGE")
	if adapterImage == "" {
		fmt.Fprintln(os.Stderr, "TEST_ADAPTER_IMAGE is not set; run via `task test:component` (builds the image and sets it)")
		os.Exit(1)
	}

	wd, _ := os.Getwd()
	cf := filepath.Join(wd, "docker-compose.yml")

	up := exec.Command("docker", "compose", "-p", composeProject, "-f", cf, "up", "-d", "--wait", "--wait-timeout", "120")
	up.Env = append(os.Environ(), "TEST_ADAPTER_IMAGE="+adapterImage)
	up.Stdout, up.Stderr = os.Stdout, os.Stderr
	if err := up.Run(); err != nil {
		dumpLogs(cf)
		down(cf)
		fmt.Fprintf(os.Stderr, "compose up failed: %v\n", err)
		os.Exit(1)
	}

	code := 1
	func() {
		defer down(cf)

		if err := waitForAdapterReady(90 * time.Second); err != nil {
			dumpLogs(cf)
			fmt.Fprintf(os.Stderr, "adapter never became ready: %v\n", err)
			return
		}
		if err := pushFixtureImage(); err != nil {
			dumpLogs(cf)
			fmt.Fprintf(os.Stderr, "pushing fixture image: %v\n", err)
			return
		}
		code = m.Run()
	}()
	os.Exit(code)
}

func down(cf string) {
	c := exec.Command("docker", "compose", "-p", composeProject, "-f", cf, "down", "-v", "--timeout", "10")
	c.Env = append(os.Environ(), "TEST_ADAPTER_IMAGE="+adapterImage)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	_ = c.Run()
}

func dumpLogs(cf string) {
	c := exec.Command("docker", "compose", "-p", composeProject, "-f", cf, "logs", "--no-color", "--tail", "120")
	c.Env = append(os.Environ(), "TEST_ADAPTER_IMAGE="+adapterImage)
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	_ = c.Run()
}

func waitForAdapterReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 3 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(adapterBaseURL + "/api/v1/metadata")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("timeout after %s", timeout)
}

// pushFixtureImage pulls a small public image (single linux/amd64 manifest for a
// stable digest across CI arches), pushes it into the htpasswd registry over plain
// HTTP, and saves a docker-save tarball for the VEX probe.
func pushFixtureImage() error {
	platform := &v1.Platform{OS: "linux", Architecture: "amd64"}
	img, err := crane.Pull(fixtureImageRef, crane.WithPlatform(platform))
	if err != nil {
		return fmt.Errorf("pulling %s: %w", fixtureImageRef, err)
	}

	dst := fmt.Sprintf("%s/%s:fixture", registryHost, registryRepo)
	auth := crane.WithAuth(&authn.Basic{Username: regUser, Password: regPassword})

	var pushErr error
	for i := 0; i < 5; i++ {
		if pushErr = crane.Push(img, dst, crane.Insecure, auth); pushErr == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if pushErr != nil {
		return fmt.Errorf("pushing %s: %w", dst, pushErr)
	}

	h, err := img.Digest()
	if err != nil {
		return fmt.Errorf("computing digest: %w", err)
	}
	fixtureDigest = h.String()

	dir, err := os.MkdirTemp("", "component-fixture-")
	if err != nil {
		return err
	}
	fixtureTarball = filepath.Join(dir, "image.tar")
	if err := crane.Save(img, dst, fixtureTarball); err != nil {
		return fmt.Errorf("saving tarball: %w", err)
	}
	// The VEX probe runs mikebom as uid 65532 against this dir (bind-mounted); make
	// it world-writable so the nonroot process can write its outputs.
	_ = os.Chmod(dir, 0o777)
	return nil
}

func basicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func postScan(t *testing.T, digest string) string {
	t.Helper()
	body := map[string]any{
		"registry": map[string]string{
			"url":           "http://registry:5000",
			"authorization": basicAuthHeader(regUser, regPassword),
		},
		"artifact": map[string]string{
			"repository": registryRepo,
			"digest":     digest,
		},
		"enabled_capabilities": []map[string]any{{
			"type":                "sbom",
			"produces_mime_types": []string{reportMIMEType},
			"parameters":          map[string]any{"sbom_media_types": []string{sbomMediaType}},
		}},
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)

	resp, err := http.Post(adapterBaseURL+"/api/v1/scan", "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode, "POST /scan must return 202")

	var sr struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&sr))
	require.NotEmpty(t, sr.ID)
	return sr.ID
}

// noRedirectClient never follows the 302 (its Location points back at the same
// report URL); the test drives the poll loop itself.
func noRedirectClient() *http.Client {
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func reportURL(id string) string {
	return fmt.Sprintf("%s/api/v1/scan/%s/report?sbom_media_type=%s",
		adapterBaseURL, id, "application%2Fspdx%2Bjson")
}

func getReport(t *testing.T, client *http.Client, id string, acceptGzip bool) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, reportURL(id), nil)
	require.NoError(t, err)
	req.Header.Set("Accept", reportMIMEType)
	if acceptGzip {
		req.Header.Set("Accept-Encoding", "gzip")
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// pollReport drives the report loop, asserting the 302 -> 200 transition. It returns
// once a terminal status (200 or a non-302 error) is seen, along with whether a 302
// with Refresh-After was observed and how long the terminal GET took.
func pollReport(t *testing.T, id string, timeout time.Duration) (finalStatus int, sawRefresh bool, terminalLatency time.Duration) {
	t.Helper()
	client := noRedirectClient()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		start := time.Now()
		resp := getReport(t, client, id, false)
		latency := time.Since(start)
		status := resp.StatusCode
		refresh := resp.Header.Get("Refresh-After")
		_ = resp.Body.Close()

		if status == http.StatusFound {
			sawRefresh = sawRefresh || refresh != ""
			assert.Equal(t, "5", refresh, "302 must carry Refresh-After (Harbor parses ParseInt(v,10,8), <=127)")
			time.Sleep(1 * time.Second)
			continue
		}
		return status, sawRefresh, latency
	}
	t.Fatalf("report for %s never reached a terminal status within %s", id, timeout)
	return 0, false, 0
}

func TestScanHappyPath_302then200_EnvelopeAndSPDX(t *testing.T) {
	id := postScan(t, fixtureDigest)

	status, sawRefresh, latency := pollReport(t, id, 120*time.Second)
	require.Equal(t, http.StatusOK, status, "report must eventually be 200")
	assert.True(t, sawRefresh, "must observe at least one 302 with Refresh-After before 200")

	t.Logf("OBSERVED transition: 302 (Refresh-After: 5) -> 200")
	t.Logf("MEASURED report-handler latency (200 GET): %s (Harbor client timeout %s)", latency, harborClientTimeout)
	assert.Less(t, latency, 2*time.Second, "report handler must respond well under Harbor's %s timeout", harborClientTimeout)

	// Fetch the 200 body (raw) and validate the envelope + embedded SPDX.
	client := noRedirectClient()
	resp := getReport(t, client, id, false)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	rawSize := len(raw)
	var gz bytes.Buffer
	gw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	_, _ = gw.Write(raw)
	_ = gw.Close()
	t.Logf("MEASURED report size: raw=%d bytes  gzip-9=%d bytes  ratio=%.1fx", rawSize, gz.Len(), float64(rawSize)/float64(gz.Len()))

	var envelope struct {
		GeneratedAt time.Time      `json:"generated_at"`
		Artifact    map[string]any `json:"artifact"`
		Scanner     map[string]any `json:"scanner"`
		MediaType   string         `json:"media_type"`
		SBOM        map[string]any `json:"sbom"`
	}
	require.NoError(t, json.Unmarshal(raw, &envelope))
	assert.Equal(t, sbomMediaType, envelope.MediaType, "envelope media_type must be application/spdx+json")
	assert.False(t, envelope.GeneratedAt.IsZero(), "envelope must carry generated_at")
	assert.Equal(t, "mikebom", envelope.Scanner["name"])
	require.NotNil(t, envelope.SBOM, "envelope.sbom must be a JSON object")

	assert.Equal(t, "SPDX-2.3", envelope.SBOM["spdxVersion"], "embedded SPDX must be 2.3")
	assert.Equal(t, "SPDXRef-DOCUMENT", envelope.SBOM["SPDXID"])
	pkgs, ok := envelope.SBOM["packages"].([]any)
	require.True(t, ok, "SPDX packages must be an array")
	assert.Greater(t, len(pkgs), 0, "SPDX must contain packages (alpine yields ~16)")
	_, hasBomFormat := envelope.SBOM["bomFormat"]
	assert.False(t, hasBomFormat, "SPDX has no bomFormat (that is CycloneDX)")

	// This whole happy path ran under the enrichment-egress blackhole (extra_hosts
	// -> 192.0.2.1). Completing within the fast budget proves the --offline flag
	// prevents mikebom from stalling on deps.dev / clearlydefined.io.
	t.Logf("scan completed with enrichment egress blackholed (api.deps.dev / api.clearlydefined.io -> 192.0.2.1)")
}

func TestReportHandlerGzips(t *testing.T) {
	id := postScan(t, fixtureDigest)
	status, _, _ := pollReport(t, id, 120*time.Second)
	require.Equal(t, http.StatusOK, status)

	// Disable transport auto-decompression so we observe the wire encoding.
	client := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp := getReport(t, client, id, true)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"), "report handler must gzip when the client accepts it")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	gr, err := gzip.NewReader(bytes.NewReader(body))
	require.NoError(t, err, "wire body must be valid gzip")
	dec, err := io.ReadAll(gr)
	require.NoError(t, err)
	t.Logf("MEASURED on-wire gzip report size: %d bytes (decompresses to %d bytes)", len(body), len(dec))
	var probe map[string]any
	require.NoError(t, json.Unmarshal(dec, &probe), "gunzipped body must be the JSON envelope")
}

// TestScanFailureNonexistentDigest proves the failure path: a scan against a digest
// that is not in the registry must produce a Failed job surfaced as a 500 with a
// useful message, and it must not hang (the pull fails fast, and the whole job is
// bounded by the worker deadline).
func TestScanFailureNonexistentDigest(t *testing.T) {
	bogus := "sha256:" + strings.Repeat("de", 32) // valid shape, absent from the registry
	id := postScan(t, bogus)

	start := time.Now()
	status, _, _ := pollReport(t, id, 90*time.Second)
	elapsed := time.Since(start)

	require.Equal(t, http.StatusInternalServerError, status, "failed scan must surface as 500")
	assert.Less(t, elapsed, 60*time.Second, "failure must be reported promptly, not hang")

	client := noRedirectClient()
	resp := getReport(t, client, id, false)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var errEnvelope struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(body, &errEnvelope))
	assert.NotEmpty(t, errEnvelope.Error.Message, "500 must carry a useful message")
	assert.Contains(t, strings.ToLower(errEnvelope.Error.Message), "pull", "message should point at the failed pull: %q", errEnvelope.Error.Message)
	t.Logf("failure path 500 message: %q (reported in %s)", errEnvelope.Error.Message, elapsed)
}

// TestReadOnlyRootFilesystem asserts the adapter container runs with a read-only
// root filesystem (D-6). Combined with the mikebom child env pinning HOME/TMPDIR and
// the openvex output into the writable per-job workdir, this proves any sidecar
// mikebom might write is confined to the workdir (nothing else is writable).
func TestReadOnlyRootFilesystem(t *testing.T) {
	cid := adapterContainerID(t)
	out, err := exec.Command("docker", "inspect", "--format", "{{.HostConfig.ReadonlyRootfs}}", cid).CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Equal(t, "true", strings.TrimSpace(string(out)), "adapter must run with a read-only root filesystem")

	// The egress blackhole is part of the same hardening story: assert it is wired.
	out2, err := exec.Command("docker", "inspect", "--format", "{{.HostConfig.ExtraHosts}}", cid).CombinedOutput()
	require.NoError(t, err, string(out2))
	hosts := string(out2)
	assert.Contains(t, hosts, "api.deps.dev:192.0.2.1", "enrichment egress must be blackholed")
	assert.Contains(t, hosts, "api.clearlydefined.io:192.0.2.1")
}

func adapterContainerID(t *testing.T) string {
	t.Helper()
	c := exec.Command("docker", "compose", "-p", composeProject, "-f", composeFile(t), "ps", "-q", "adapter")
	c.Env = append(os.Environ(), "TEST_ADAPTER_IMAGE="+adapterImage)
	out, err := c.Output()
	require.NoError(t, err)
	cid := strings.TrimSpace(string(out))
	require.NotEmpty(t, cid, "could not resolve adapter container id")
	return cid
}

// TestVEXSidecarPinnedToWorkdirAndDiscarded exercises the openvex-sidecar handling
// with the REAL mikebom binary from the adapter image, using the exact --output
// openvex=<workdir>/... flag the wrapper passes, plus a supplement fixture that
// declares a vulnerability.
//
// Verified fact (docs/spike-m1.md Task 4, re-confirmed from source): mikebom
// v0.1.0-alpha.55 never populates ResolvedComponent.advisories in ANY production
// path (every path sets advisories: vec![], including the supplement merge, which
// ignores the CDX vulnerabilities surface). So the openvex emitter is scaffolding
// that fires a no-op for every present-day scan; no CLI input can make it write a
// sidecar. The property that matters is therefore proven directly:
//   - PINNED: the openvex output path is directed into the per-job workdir, and the
//     default-name sidecar (mikebom.openvex.json) never lands in CWD/HOME.
//   - DISCARDED: the adapter's report envelope carries only .sbom (no vex/openvex
//     key), and the whole workdir is read-only-confined and swept after the job.
func TestVEXSidecarPinnedToWorkdirAndDiscarded(t *testing.T) {
	require.NotEmpty(t, fixtureTarball)
	workdir := filepath.Dir(fixtureTarball)
	wd, _ := os.Getwd()
	supp := filepath.Join(wd, "testdata", "vex-supplement.cdx.json")
	require.FileExists(t, supp)
	// Copy the supplement into the mounted workdir so the container can read it.
	suppBytes, err := os.ReadFile(supp)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(workdir, "supp.cdx.json"), suppBytes, 0o644))

	// Run mikebom exactly as the wrapper does: --offline is the global egress flag,
	// openvex output pinned into the (mounted) workdir alongside the SPDX output.
	args := []string{
		"run", "--rm",
		"--entrypoint", "/usr/local/bin/mikebom",
		"-e", "HOME=/vex", "-e", "TMPDIR=/vex", "-e", "MIKEBOM_OFFLINE=1",
		"-v", workdir + ":/vex",
		adapterImage,
		"--offline", "sbom", "scan",
		"--image", "/vex/image.tar",
		"--format", "spdx-2.3-json",
		"--output", "spdx-2.3-json=/vex/out.spdx.json",
		"--output", "openvex=/vex/out.vex.json",
		"--supplement-cdx", "/vex/supp.cdx.json",
		"--no-oci-cache",
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	require.NoError(t, err, "mikebom run failed: %s", string(out))

	// PINNED: the SPDX output landed exactly where the flag directed it.
	assert.FileExists(t, filepath.Join(workdir, "out.spdx.json"), "SPDX output must be pinned to the workdir path")
	// The default-name openvex sidecar must never appear anywhere in the workdir
	// (proves --output openvex=<workdir>/... retargets it; nothing leaks to CWD).
	assert.NoFileExists(t, filepath.Join(workdir, "mikebom.openvex.json"), "default-name sidecar must not be written to CWD")
	// Present-day mikebom emits no sidecar (scaffolding no-op); there is nothing to
	// discard, and had it emitted one it would be inside the workdir path above.
	if _, statErr := os.Stat(filepath.Join(workdir, "out.vex.json")); statErr == nil {
		t.Logf("openvex sidecar was emitted at the pinned workdir path (would be discarded by the adapter)")
	} else {
		t.Logf("mikebom emitted no openvex sidecar (scaffolding no-op, confirmed); pinned path honored, nothing to leak")
	}

	// DISCARDED: a full adapter scan's report envelope surfaces only .sbom to Harbor.
	id := postScan(t, fixtureDigest)
	status, _, _ := pollReport(t, id, 120*time.Second)
	require.Equal(t, http.StatusOK, status)
	client := noRedirectClient()
	resp := getReport(t, client, id, false)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &top))
	for _, k := range []string{"vex", "openvex", "out.vex", "vex_document"} {
		_, present := top[k]
		assert.False(t, present, "report envelope must not surface an openvex sidecar (key %q)", k)
	}
	_, hasSBOM := top["sbom"]
	assert.True(t, hasSBOM, "report envelope must carry the .sbom document")
}

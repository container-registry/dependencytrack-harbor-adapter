package waybill

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
)

const testImageRef = "core:8080/library/alpine@sha256:deadbeef"

// writeStub writes a fake waybill shell-script binary. mode selects behavior:
//
//	ok       -> --version prints a version; scan writes SPDX and argv/env dumps, exit 0
//	timeout  -> scan exits 124 (waybill's own --timeout convention)
//	fail     -> scan writes to stderr, exit 2
//	pullauth -> scan writes waybill's own 401 message to stderr, exit 1
//	pulltls  -> scan writes waybill's own TLS-handshake message to stderr, exit 1
//	hang     -> scan sleeps 30s (to exercise the ctx/backstop path)
//
// The stub cannot read a mode from env (the wrapper strips the environment), so
// the mode is baked into each generated script.
func writeStub(t *testing.T, mode string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("exec-stub uses a POSIX shell script")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "waybill")

	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "waybill 0.1.0-alpha.69"
  exit 0
fi

# Locate the SPDX output path from "--output spdx-2.3-json=PATH".
out=""
for a in "$@"; do
  case "$a" in
    spdx-2.3-json=*) out="${a#spdx-2.3-json=}" ;;
  esac
done
outdir=$(dirname "$out")

# Record argv and env so the test can assert the allowlist and flags.
: > "$outdir/argv.txt"
for a in "$@"; do printf '%s\n' "$a" >> "$outdir/argv.txt"; done
env > "$outdir/env.txt"

MODE=` + mode + `
case "$MODE" in
  timeout) exit 124 ;;
  fail) echo "boom: something failed" 1>&2; exit 2 ;;
  pullauth) echo "Error: registry returned 401 with Basic auth challenge for GET http://core:8080/v2/library/alpine/manifests/sha256:deadbeef, but no credentials are configured for this registry." 1>&2; exit 1 ;;
  pulltls) echo "Error: TLS handshake failed for GET https://core:8080/v2/library/alpine/manifests/sha256:deadbeef. If this registry uses plain HTTP, pass --insecure-registry core:8080." 1>&2; exit 1 ;;
  hang) sleep 30 ;;
esac

cat > "$out" <<'JSON'
{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"stub","packages":[{"name":"musl","SPDXID":"SPDXRef-Package-musl"}]}
JSON
exit 0
`
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return path
}

func baseConfig(binary string) etc.Waybill {
	return etc.Waybill{
		Binary:  binary,
		Timeout: 5 * time.Minute,
	}
}

func target() ScanTarget {
	return ScanTarget{ImageRef: testImageRef}
}

func TestVersion(t *testing.T) {
	w := NewWrapper(baseConfig(writeStub(t, "ok")))
	v, err := w.Version(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "0.1.0-alpha.69", v)
}

func TestScanTarget_Registry(t *testing.T) {
	tests := []struct {
		ref  string
		want string
	}{
		{"core:8080/library/alpine@sha256:deadbeef", "core:8080"},
		{"core.harbor.domain:443/a/b/c@sha256:deadbeef", "core.harbor.domain:443"},
		{"noslash", ""},
		{"", ""},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, ScanTarget{ImageRef: tc.ref}.Registry(), tc.ref)
	}
}

// TestRegistryEnvKey pins the mirror of waybill's own credential-env-var key
// derivation (auth.rs normalize_registry_key + uppercase/non-alnum-to-underscore).
// If this drifts, per-registry credentials silently stop resolving.
func TestRegistryEnvKey(t *testing.T) {
	tests := []struct{ in, want string }{
		{"core:8080", "CORE_8080"},
		{"localhost:5555", "LOCALHOST_5555"},
		{"core.harbor.domain:443", "CORE_HARBOR_DOMAIN_443"},
		{"ghcr.io", "GHCR_IO"},
		{"GHCR.IO", "GHCR_IO"},
		{"my-ecr.amazonaws.com", "MY_ECR_AMAZONAWS_COM"},
		{"https://index.docker.io/v1/", "DOCKER_IO"},
		{"", ""},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, registryEnvKey(tc.in), tc.in)
	}
}

func TestGenerateSBOM_OK(t *testing.T) {
	w := NewWrapper(baseConfig(writeStub(t, "ok")))
	jobDir := t.TempDir()

	raw, err := w.GenerateSBOM(context.Background(), target(), jobDir)
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	assert.Equal(t, "SPDX-2.3", doc["spdxVersion"])
}

func TestGenerateSBOM_EmptyRefRejected(t *testing.T) {
	w := NewWrapper(baseConfig(writeStub(t, "ok")))
	_, err := w.GenerateSBOM(context.Background(), ScanTarget{}, t.TempDir())
	require.Error(t, err)
}

// TestGenerateSBOM_ArgvHasOffline is the argv-level proof that the wrapper passes
// --offline (the real egress control) and the SBOM flags, per docs/spike-m1.md.
func TestGenerateSBOM_ArgvHasOffline(t *testing.T) {
	w := NewWrapper(baseConfig(writeStub(t, "ok")))
	jobDir := t.TempDir()

	_, err := w.GenerateSBOM(context.Background(), target(), jobDir)
	require.NoError(t, err)

	argv := readLines(t, filepath.Join(jobDir, "argv.txt"))
	assert.Contains(t, argv, "--offline", "wrapper must pass --offline in argv (env var alone does not disable enrichment)")
	assert.Contains(t, argv, "--no-oci-cache")
	assert.Contains(t, argv, "spdx-2.3-json")
	assert.Contains(t, argv, "--timeout")
	assert.Contains(t, argv, "300") // 5m in whole seconds

	// --offline must precede the "sbom" subcommand (it is a global flag).
	offlineIdx := indexOf(argv, "--offline")
	sbomIdx := indexOf(argv, "sbom")
	require.GreaterOrEqual(t, offlineIdx, 0)
	require.GreaterOrEqual(t, sbomIdx, 0)
	assert.Less(t, offlineIdx, sbomIdx, "--offline is a global flag; it must come before 'sbom scan'")
}

// TestGenerateSBOM_ArgvPinsRemoteSource is the regression pin for the native-pull
// switch: the reference goes to waybill verbatim and --image-src is pinned to
// remote. waybill's default order is docker,podman,remote, which would probe a
// container runtime the adapter image does not ship.
func TestGenerateSBOM_ArgvPinsRemoteSource(t *testing.T) {
	w := NewWrapper(baseConfig(writeStub(t, "ok")))
	jobDir := t.TempDir()

	_, err := w.GenerateSBOM(context.Background(), target(), jobDir)
	require.NoError(t, err)

	argv := readLines(t, filepath.Join(jobDir, "argv.txt"))
	assert.Contains(t, argv, "--image")
	assert.Contains(t, argv, testImageRef)
	srcIdx := indexOf(argv, "--image-src")
	require.GreaterOrEqual(t, srcIdx, 0, "--image-src must be pinned, never defaulted")
	require.Less(t, srcIdx+1, len(argv))
	assert.Equal(t, "remote", argv[srcIdx+1])
}

// TestGenerateSBOM_TransportFlags covers the waybill m182 transport surface the
// adapter drives: plain-HTTP registries, private CA bundles, and skip-verify.
func TestGenerateSBOM_TransportFlags(t *testing.T) {
	t.Run("insecure registry only when http", func(t *testing.T) {
		w := NewWrapper(baseConfig(writeStub(t, "ok")))
		jobDir := t.TempDir()
		_, err := w.GenerateSBOM(context.Background(), ScanTarget{ImageRef: testImageRef, Insecure: true}, jobDir)
		require.NoError(t, err)

		argv := readLines(t, filepath.Join(jobDir, "argv.txt"))
		idx := indexOf(argv, "--insecure-registry")
		require.GreaterOrEqual(t, idx, 0)
		assert.Equal(t, "core:8080", argv[idx+1], "the matcher value must be the host:port from the reference")
	})

	t.Run("no insecure registry when https", func(t *testing.T) {
		w := NewWrapper(baseConfig(writeStub(t, "ok")))
		jobDir := t.TempDir()
		_, err := w.GenerateSBOM(context.Background(), target(), jobDir)
		require.NoError(t, err)

		argv := readLines(t, filepath.Join(jobDir, "argv.txt"))
		assert.NotContains(t, argv, "--insecure-registry")
	})

	t.Run("ca certs and skip verify", func(t *testing.T) {
		cfg := baseConfig(writeStub(t, "ok"))
		cfg.RegistryCACerts = []string{"/etc/ca/one.pem", "/etc/ca/two.pem"}
		cfg.InsecureSkipVerify = true
		w := NewWrapper(cfg)
		jobDir := t.TempDir()
		_, err := w.GenerateSBOM(context.Background(), target(), jobDir)
		require.NoError(t, err)

		argv := readLines(t, filepath.Join(jobDir, "argv.txt"))
		assert.Contains(t, argv, "/etc/ca/one.pem")
		assert.Contains(t, argv, "/etc/ca/two.pem")
		assert.Equal(t, 2, countOf(argv, "--registry-ca-cert"), "--registry-ca-cert is repeatable, one per bundle")
		assert.Contains(t, argv, "--insecure-tls-skip-verify")
	})
}

// TestGenerateSBOM_CredentialsGoThroughEnv proves credentials reach waybill via
// the environment and never via argv, which is world-readable through /proc.
func TestGenerateSBOM_CredentialsGoThroughEnv(t *testing.T) {
	w := NewWrapper(baseConfig(writeStub(t, "ok")))
	jobDir := t.TempDir()

	tgt := ScanTarget{ImageRef: testImageRef, Username: "robot$scanner", Password: "s3cr3t"}
	_, err := w.GenerateSBOM(context.Background(), tgt, jobDir)
	require.NoError(t, err)

	env := readLines(t, filepath.Join(jobDir, "env.txt"))
	assert.Equal(t, "robot$scanner", envValue(env, "WAYBILL_REGISTRY_CORE_8080_USERNAME"))
	assert.Equal(t, "s3cr3t", envValue(env, "WAYBILL_REGISTRY_CORE_8080_PASSWORD"))
	assert.Equal(t, "robot$scanner", envValue(env, "WAYBILL_REGISTRY_USERNAME"))
	assert.Equal(t, "s3cr3t", envValue(env, "WAYBILL_REGISTRY_PASSWORD"))

	argv := readLines(t, filepath.Join(jobDir, "argv.txt"))
	for _, a := range argv {
		assert.NotContains(t, a, "s3cr3t", "the secret must never appear in argv")
		assert.NotContains(t, a, "robot$scanner")
	}
}

// TestGenerateSBOM_AnonymousSetsNoCredentials pins that an empty authorization
// leaves waybill in anonymous mode rather than sending an empty Basic pair.
func TestGenerateSBOM_AnonymousSetsNoCredentials(t *testing.T) {
	w := NewWrapper(baseConfig(writeStub(t, "ok")))
	jobDir := t.TempDir()

	_, err := w.GenerateSBOM(context.Background(), target(), jobDir)
	require.NoError(t, err)

	env := readLines(t, filepath.Join(jobDir, "env.txt"))
	assert.False(t, hasEnv(env, "WAYBILL_REGISTRY_USERNAME"))
	assert.False(t, hasEnv(env, "WAYBILL_REGISTRY_PASSWORD"))
	assert.False(t, hasEnv(env, "WAYBILL_REGISTRY_CORE_8080_USERNAME"))
}

// TestGenerateSBOM_EnrichmentDropsOffline proves enrichment opt-in removes
// --offline and WAYBILL_OFFLINE.
func TestGenerateSBOM_EnrichmentDropsOffline(t *testing.T) {
	cfg := baseConfig(writeStub(t, "ok"))
	cfg.Enrichment = true
	w := NewWrapper(cfg)
	jobDir := t.TempDir()

	_, err := w.GenerateSBOM(context.Background(), target(), jobDir)
	require.NoError(t, err)

	argv := readLines(t, filepath.Join(jobDir, "argv.txt"))
	assert.NotContains(t, argv, "--offline")
	env := readLines(t, filepath.Join(jobDir, "env.txt"))
	assert.False(t, hasEnv(env, "WAYBILL_OFFLINE"), "enrichment on: WAYBILL_OFFLINE must be absent")
}

// TestGenerateSBOM_ChildEnvIsAllowlist proves the child env is a constructed
// allowlist and NOT the inherited process environment: a secret set on the
// parent must not appear in the child, while HOME/TMPDIR/WAYBILL_OFFLINE do.
// HOME and TMPDIR pinned to the per-job dir is also what keeps waybill's blob
// cache and layer-extraction scratch inside the directory the controller deletes.
func TestGenerateSBOM_ChildEnvIsAllowlist(t *testing.T) {
	t.Setenv("SCANNER_API_AUTH_API_KEY", "super-secret-should-not-leak")
	t.Setenv("SCANNER_REDIS_URL", "redis://user:password@redis:6379")

	w := NewWrapper(baseConfig(writeStub(t, "ok")))
	jobDir := t.TempDir()

	_, err := w.GenerateSBOM(context.Background(), target(), jobDir)
	require.NoError(t, err)

	env := readLines(t, filepath.Join(jobDir, "env.txt"))
	assert.False(t, hasEnv(env, "SCANNER_API_AUTH_API_KEY"), "adapter secrets must not leak into the waybill child")
	assert.False(t, hasEnv(env, "SCANNER_REDIS_URL"))
	assert.True(t, hasEnv(env, "HOME"))
	assert.True(t, hasEnv(env, "TMPDIR"))
	assert.True(t, hasEnv(env, "WAYBILL_OFFLINE"))

	assert.Equal(t, jobDir, envValue(env, "HOME"))
	assert.Equal(t, jobDir, envValue(env, "TMPDIR"))
	assert.Equal(t, "1", envValue(env, "WAYBILL_OFFLINE"))
}

func TestGenerateSBOM_Exit124IsTimeout(t *testing.T) {
	w := NewWrapper(baseConfig(writeStub(t, "timeout")))
	jobDir := t.TempDir()

	_, err := w.GenerateSBOM(context.Background(), target(), jobDir)
	require.Error(t, err)
	var wErr *Error
	require.ErrorAs(t, err, &wErr)
	assert.Equal(t, CategoryTimeout, wErr.Category)
	assert.Equal(t, 124, wErr.ExitCode)
}

func TestGenerateSBOM_NonZeroIsExecError(t *testing.T) {
	w := NewWrapper(baseConfig(writeStub(t, "fail")))
	jobDir := t.TempDir()

	_, err := w.GenerateSBOM(context.Background(), target(), jobDir)
	require.Error(t, err)
	var wErr *Error
	require.ErrorAs(t, err, &wErr)
	assert.Equal(t, CategoryExec, wErr.Category)
	assert.Contains(t, wErr.Detail, "boom")
}

// TestGenerateSBOM_PullFailuresAreClassified covers the categories that only
// exist because the pull moved inside the subprocess: without them a 401 from the
// registry and a genuine scanner crash are indistinguishable in Harbor's UI.
func TestGenerateSBOM_PullFailuresAreClassified(t *testing.T) {
	tests := []struct {
		mode string
		want ErrorCategory
	}{
		{"pullauth", CategoryPullAuth},
		{"pulltls", CategoryPullTransport},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			w := NewWrapper(baseConfig(writeStub(t, tc.mode)))
			_, err := w.GenerateSBOM(context.Background(), target(), t.TempDir())
			require.Error(t, err)
			var wErr *Error
			require.ErrorAs(t, err, &wErr)
			assert.Equal(t, tc.want, wErr.Category)
			assert.Contains(t, wErr.Detail, testImageRef, "the failing reference must be in the message")
		})
	}
}

// TestGenerateSBOM_ContextBackstop exercises the timeout path via a hanging stub
// and a short parent context (the backstop that guards against waybill's own
// timer wedging).
func TestGenerateSBOM_ContextBackstop(t *testing.T) {
	w := NewWrapper(baseConfig(writeStub(t, "hang")))
	jobDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := w.GenerateSBOM(ctx, target(), jobDir)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 25*time.Second, "must not wait for the hanging stub")
	var wErr *Error
	require.ErrorAs(t, err, &wErr)
	assert.Equal(t, CategoryTimeout, wErr.Category)
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

func countOf(ss []string, want string) int {
	n := 0
	for _, s := range ss {
		if s == want {
			n++
		}
	}
	return n
}

func hasEnv(env []string, key string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, key+"=") {
			return true
		}
	}
	return false
}

func envValue(env []string, key string) string {
	for _, e := range env {
		if strings.HasPrefix(e, key+"=") {
			return strings.TrimPrefix(e, key+"=")
		}
	}
	return ""
}

package mikebom

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

	"github.com/container-registry/mikebom-harbor-adapter/pkg/etc"
)

// writeStub writes a fake mikebom shell-script binary. mode selects behavior:
//
//	ok       -> --version prints a version; scan writes SPDX and argv/env dumps, exit 0
//	timeout  -> scan exits 124 (mikebom's own --timeout convention)
//	fail     -> scan writes to stderr, exit 2
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
	path := filepath.Join(dir, "mikebom")

	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "mikebom 0.1.0-alpha.55"
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

func baseConfig(binary string) etc.Mikebom {
	return etc.Mikebom{
		Binary:  binary,
		Timeout: 5 * time.Minute,
	}
}

func TestVersion(t *testing.T) {
	w := NewWrapper(baseConfig(writeStub(t, "ok")))
	v, err := w.Version(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "0.1.0-alpha.55", v)
}

func TestGenerateSBOM_OK(t *testing.T) {
	stub := writeStub(t, "ok")
	w := NewWrapper(baseConfig(stub))
	jobDir := t.TempDir()

	raw, err := w.GenerateSBOM(context.Background(), filepath.Join(jobDir, "image.tar"), jobDir)
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	assert.Equal(t, "SPDX-2.3", doc["spdxVersion"])
}

// TestGenerateSBOM_ArgvHasOffline is the argv-level proof that the wrapper passes
// --offline (the real egress control) and the SBOM flags, per docs/spike-m1.md.
func TestGenerateSBOM_ArgvHasOffline(t *testing.T) {
	stub := writeStub(t, "ok")
	w := NewWrapper(baseConfig(stub))
	jobDir := t.TempDir()

	_, err := w.GenerateSBOM(context.Background(), filepath.Join(jobDir, "image.tar"), jobDir)
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

// TestGenerateSBOM_EnrichmentDropsOffline proves enrichment opt-in removes
// --offline and MIKEBOM_OFFLINE.
func TestGenerateSBOM_EnrichmentDropsOffline(t *testing.T) {
	cfg := baseConfig(writeStub(t, "ok"))
	cfg.Enrichment = true
	w := NewWrapper(cfg)
	jobDir := t.TempDir()

	_, err := w.GenerateSBOM(context.Background(), filepath.Join(jobDir, "image.tar"), jobDir)
	require.NoError(t, err)

	argv := readLines(t, filepath.Join(jobDir, "argv.txt"))
	assert.NotContains(t, argv, "--offline")
	env := readLines(t, filepath.Join(jobDir, "env.txt"))
	assert.False(t, hasEnv(env, "MIKEBOM_OFFLINE"), "enrichment on: MIKEBOM_OFFLINE must be absent")
}

// TestGenerateSBOM_ChildEnvIsAllowlist proves the child env is a constructed
// allowlist and NOT the inherited process environment: a secret set on the
// parent must not appear in the child, while HOME/TMPDIR/MIKEBOM_OFFLINE do.
func TestGenerateSBOM_ChildEnvIsAllowlist(t *testing.T) {
	t.Setenv("SCANNER_API_AUTH_API_KEY", "super-secret-should-not-leak")
	t.Setenv("SCANNER_REDIS_URL", "redis://user:password@redis:6379")

	stub := writeStub(t, "ok")
	w := NewWrapper(baseConfig(stub))
	jobDir := t.TempDir()

	_, err := w.GenerateSBOM(context.Background(), filepath.Join(jobDir, "image.tar"), jobDir)
	require.NoError(t, err)

	env := readLines(t, filepath.Join(jobDir, "env.txt"))
	assert.False(t, hasEnv(env, "SCANNER_API_AUTH_API_KEY"), "adapter secrets must not leak into the mikebom child")
	assert.False(t, hasEnv(env, "SCANNER_REDIS_URL"))
	assert.True(t, hasEnv(env, "HOME"))
	assert.True(t, hasEnv(env, "TMPDIR"))
	assert.True(t, hasEnv(env, "MIKEBOM_OFFLINE"))

	assert.Equal(t, jobDir, envValue(env, "HOME"))
	assert.Equal(t, jobDir, envValue(env, "TMPDIR"))
	assert.Equal(t, "1", envValue(env, "MIKEBOM_OFFLINE"))
}

func TestGenerateSBOM_Exit124IsTimeout(t *testing.T) {
	w := NewWrapper(baseConfig(writeStub(t, "timeout")))
	jobDir := t.TempDir()

	_, err := w.GenerateSBOM(context.Background(), filepath.Join(jobDir, "image.tar"), jobDir)
	require.Error(t, err)
	var mErr *Error
	require.ErrorAs(t, err, &mErr)
	assert.Equal(t, CategoryTimeout, mErr.Category)
	assert.Equal(t, 124, mErr.ExitCode)
}

func TestGenerateSBOM_NonZeroIsExecError(t *testing.T) {
	w := NewWrapper(baseConfig(writeStub(t, "fail")))
	jobDir := t.TempDir()

	_, err := w.GenerateSBOM(context.Background(), filepath.Join(jobDir, "image.tar"), jobDir)
	require.Error(t, err)
	var mErr *Error
	require.ErrorAs(t, err, &mErr)
	assert.Equal(t, CategoryExec, mErr.Category)
	assert.Contains(t, mErr.Detail, "boom")
}

// TestGenerateSBOM_ContextBackstop exercises the timeout path via a hanging stub
// and a short parent context (the backstop that guards against mikebom's own
// timer wedging).
func TestGenerateSBOM_ContextBackstop(t *testing.T) {
	w := NewWrapper(baseConfig(writeStub(t, "hang")))
	jobDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := w.GenerateSBOM(ctx, filepath.Join(jobDir, "image.tar"), jobDir)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 25*time.Second, "must not wait for the hanging stub")
	var mErr *Error
	require.ErrorAs(t, err, &mErr)
	assert.Equal(t, CategoryTimeout, mErr.Category)
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

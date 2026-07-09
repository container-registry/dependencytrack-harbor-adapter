package etc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetConfigDefaults(t *testing.T) {
	cfg, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, ":8080", cfg.API.Addr)
	assert.Equal(t, "/usr/local/bin/mikebom", cfg.Mikebom.Binary)
	assert.Equal(t, "/home/scanner/work", cfg.Mikebom.WorkDir)
	assert.Equal(t, 5*time.Minute, cfg.Mikebom.Timeout)
	assert.False(t, cfg.Mikebom.Enrichment)
	assert.Equal(t, "harbor.scanner.mikebom:data-store", cfg.RedisStore.Namespace)
	assert.Equal(t, "harbor.scanner.mikebom:job-queue", cfg.JobQueue.Namespace)
	assert.Equal(t, "redis", cfg.Store.Backend)
}

func TestLockTTLDerivedFromTimeout(t *testing.T) {
	t.Setenv("SCANNER_MIKEBOM_TIMEOUT", "2m")
	cfg, err := GetConfig()
	require.NoError(t, err)
	// Not a copied 5m constant: TTL tracks the configured scan timeout + backstop.
	assert.Equal(t, 2*time.Minute+30*time.Second, cfg.LockTTL())
}

type fakeVersioner struct {
	v   string
	err error
}

func (f fakeVersioner) Version(context.Context) (string, error) { return f.v, f.err }

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

func TestCheck_OK(t *testing.T) {
	dir := t.TempDir()
	cfg, err := GetConfig()
	require.NoError(t, err)
	cfg.Mikebom.WorkDir = filepath.Join(dir, "work")
	cfg.Store.Backend = "redis"

	err = Check(context.Background(), cfg, fakeVersioner{v: "0.1.0-alpha.55"}, fakePinger{})
	require.NoError(t, err)
}

func TestCheck_MikebomNotExecable(t *testing.T) {
	cfg, err := GetConfig()
	require.NoError(t, err)
	cfg.Mikebom.WorkDir = t.TempDir()
	cfg.Store.Backend = "memory"

	err = Check(context.Background(), cfg, fakeVersioner{err: errors.New("no such file")}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not exec-able")
}

func TestCheck_RedisUnreachable(t *testing.T) {
	cfg, err := GetConfig()
	require.NoError(t, err)
	cfg.Mikebom.WorkDir = t.TempDir()
	cfg.Store.Backend = "redis"

	err = Check(context.Background(), cfg, fakeVersioner{v: "v"}, fakePinger{err: errors.New("connection refused")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redis not reachable")
}

func TestSweepStaleWorkDirs(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "scan-abc"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "scan-def"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "keep"), 0o700))

	require.NoError(t, SweepStaleWorkDirs(dir))

	_, err := os.Stat(filepath.Join(dir, "scan-abc"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(dir, "scan-def"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(dir, "keep"))
	assert.NoError(t, err, "non scan-* dirs must be preserved")
}

func TestSweepStaleWorkDirs_MissingDirIsNoError(t *testing.T) {
	require.NoError(t, SweepStaleWorkDirs(filepath.Join(t.TempDir(), "does-not-exist")))
}

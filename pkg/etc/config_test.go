package etc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMemoryBackendValidatesWorkerConcurrency pins the fix for a gap the
// validation had: the memory backend returned before the concurrency check, and
// the in-process queue starts exactly WorkerConcurrency consumers. A value of 0
// therefore produced an adapter that started, reported healthy, accepted scans
// with 202, and had nobody to run them.
func TestMemoryBackendValidatesWorkerConcurrency(t *testing.T) {
	for _, backend := range []string{"memory", "redis"} {
		t.Run(backend, func(t *testing.T) {
			t.Setenv("SCANNER_STORE_BACKEND", backend)
			t.Setenv("SCANNER_JOB_QUEUE_WORKER_CONCURRENCY", "0")
			_, err := GetConfig()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "SCANNER_JOB_QUEUE_WORKER_CONCURRENCY")
		})
	}
}

func TestNegativeMaxImageSizeIsRejected(t *testing.T) {
	t.Setenv("SCANNER_WAYBILL_MAX_IMAGE_SIZE", "-1")
	_, err := GetConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SCANNER_WAYBILL_MAX_IMAGE_SIZE")
}

// TestPartialTLSIsRejected pins that a typo in one of two TLS secrets fails the
// deployment instead of silently serving plaintext. IsTLSEnabled requires both,
// so setting only one used to disable transport security without a word.
func TestPartialTLSIsRejected(t *testing.T) {
	for _, tc := range []struct{ name, cert, key string }{
		{"cert without key", "/tmp/tls.crt", ""},
		{"key without cert", "", "/tmp/tls.key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SCANNER_API_SERVER_TLS_CERTIFICATE", tc.cert)
			t.Setenv("SCANNER_API_SERVER_TLS_KEY", tc.key)
			_, err := GetConfig()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must be set together")
		})
	}
}

// TestClientCAsWithoutTLSIsRejected: client certificates are only verified on a
// TLS listener, so this combination silently verifies nothing.
func TestClientCAsWithoutTLSIsRejected(t *testing.T) {
	t.Setenv("SCANNER_API_SERVER_CLIENT_CAS", "/tmp/ca.pem")
	_, err := GetConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires TLS")
}

// TestNonPositiveServerTimeoutsAreRejected: net/http reads a zero timeout as
// "no timeout", so a typo silently removes slow-client protection rather than
// tightening it.
func TestNonPositiveServerTimeoutsAreRejected(t *testing.T) {
	for _, name := range []string{
		"SCANNER_API_SERVER_READ_TIMEOUT",
		"SCANNER_API_SERVER_WRITE_TIMEOUT",
		"SCANNER_API_SERVER_IDLE_TIMEOUT",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "0s")
			_, err := GetConfig()
			require.Error(t, err)
			assert.Contains(t, err.Error(), name)
		})
	}
}

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

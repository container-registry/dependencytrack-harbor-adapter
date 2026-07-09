package queue

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/mikebom-harbor-adapter/pkg/harbor"
	"github.com/container-registry/mikebom-harbor-adapter/pkg/job"
)

type capturingController struct {
	gotDeadline bool
	deadline    time.Time
}

func (c *capturingController) Scan(ctx context.Context, _ job.ScanJobKey, _ *harbor.ScanRequest) error {
	c.deadline, c.gotDeadline = ctx.Deadline()
	return nil
}

// TestRunJobBoundsScanByDeadline proves the whole job (pull + scan) is bounded by a
// deadline. Before the fix, controller.Scan received context.Background() straight
// from main, so an unbounded registry pull could wedge the (single) worker goroutine
// forever. runJob must hand controller.Scan a context whose deadline is ~lockTTL out.
func TestRunJobBoundsScanByDeadline(t *testing.T) {
	const lockTTL = 90 * time.Second
	ctrl := &capturingController{}
	w := &worker{lockTTL: lockTTL, controller: ctrl}

	before := time.Now()
	err := w.runJob(context.Background(), Job{})
	require.NoError(t, err)

	require.True(t, ctrl.gotDeadline, "controller.Scan must receive a context with a deadline (unbounded pull would otherwise wedge the worker)")
	remaining := time.Until(ctrl.deadline)
	assert.Greater(t, remaining, lockTTL-5*time.Second, "deadline must be ~lockTTL out")
	assert.LessOrEqual(t, remaining, lockTTL, "deadline must not exceed lockTTL")
	assert.WithinDuration(t, before.Add(lockTTL), ctrl.deadline, 5*time.Second)
}

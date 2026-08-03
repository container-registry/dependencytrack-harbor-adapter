package redis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/container-registry/waybill-harbor-adapter/pkg/etc"
	"github.com/container-registry/waybill-harbor-adapter/pkg/http/api"
	"github.com/container-registry/waybill-harbor-adapter/pkg/job"
	"github.com/container-registry/waybill-harbor-adapter/pkg/persistence"
)

// commandRecorder logs every command the store issues, which is how the write
// amplification is measured rather than asserted.
type commandRecorder struct {
	mu   sync.Mutex
	cmds []string
}

func (r *commandRecorder) DialHook(next goredis.DialHook) goredis.DialHook { return next }

func (r *commandRecorder) ProcessHook(next goredis.ProcessHook) goredis.ProcessHook {
	return func(ctx context.Context, cmd goredis.Cmder) error {
		r.mu.Lock()
		r.cmds = append(r.cmds, strings.ToUpper(cmd.Name()))
		r.mu.Unlock()
		return next(ctx, cmd)
	}
}

func (r *commandRecorder) ProcessPipelineHook(next goredis.ProcessPipelineHook) goredis.ProcessPipelineHook {
	return next
}

func (r *commandRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cmds = nil
}

func (r *commandRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.cmds...)
}

func newTestStore(t *testing.T) (*miniredis.Miniredis, persistence.Store, *commandRecorder) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	rec := &commandRecorder{}
	rdb.AddHook(rec)

	cfg := etc.RedisStore{Namespace: "test.ns", ScanJobTTL: time.Hour}
	return mr, NewStore(cfg, rdb), rec
}

func testKey() job.ScanJobKey {
	return job.ScanJobKey{ID: "abc123", MIMEType: api.MimeTypeSecuritySBOMReport, MediaType: api.MediaTypeSPDX}
}

// bigReport is deliberately repetitive, like real SPDX: thousands of package
// entries differing only in name and version.
func bigReport(packages int) json.RawMessage {
	var buf bytes.Buffer
	buf.WriteString(`{"media_type":"application/spdx+json","sbom":{"spdxVersion":"SPDX-2.3","packages":[`)
	for i := 0; i < packages; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf,
			`{"SPDXID":"SPDXRef-Package-%d","name":"github.com/example/module-%d","versionInfo":"v1.2.%d","downloadLocation":"NOASSERTION","filesAnalyzed":false,"licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION","copyrightText":"NOASSERTION"}`,
			i, i, i)
	}
	buf.WriteString(`]}}`)
	return buf.Bytes()
}

// TestFinishIsASingleWrite is the regression pin for the report write
// amplification. UpdateReport and UpdateStatus(Finished) were each a
// read-modify-write, so completing one scan moved the whole multi-MB report
// across the connection four times. Finish knows every field, so it writes once
// and reads not at all.
func TestFinishIsASingleWrite(t *testing.T) {
	_, s, rec := newTestStore(t)
	ctx := context.Background()
	key := testKey()
	require.NoError(t, s.Create(ctx, job.ScanJob{Key: key, Status: job.Queued}))

	rec.reset()
	require.NoError(t, s.Finish(ctx, key, bigReport(500)))

	assert.Equal(t, []string{"SET"}, rec.snapshot(),
		"finishing a job must be exactly one write and no read")
}

func TestFinishStoresReportAndStatus(t *testing.T) {
	_, s, _ := newTestStore(t)
	ctx := context.Background()
	key := testKey()
	require.NoError(t, s.Create(ctx, job.ScanJob{Key: key, Status: job.Queued}))

	report := json.RawMessage(`{"media_type":"application/spdx+json","sbom":{"spdxVersion":"SPDX-2.3"}}`)
	require.NoError(t, s.Finish(ctx, key, report))

	got, err := s.Get(ctx, key)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, job.Finished, got.Status)
	assert.JSONEq(t, string(report), string(got.Report))
	assert.Empty(t, got.Error)
}

// TestFinishFailsOnExpiredKey keeps the SetXX guarantee after the Get was
// dropped: a job whose TTL elapsed during a long scan must not be resurrected as
// a record Harbor would then poll forever.
func TestFinishFailsOnExpiredKey(t *testing.T) {
	_, s, _ := newTestStore(t)
	err := s.Finish(context.Background(), testKey(), json.RawMessage(`{}`))
	require.ErrorIs(t, err, persistence.ErrJobNotFound)
}

// TestStoredRecordIsCompressed measures the on-the-wire saving rather than
// asserting compression happened. SPDX is repetitive JSON, so the ratio is the
// whole point: this is what Redis holds for ScanJobTTL and re-reads on every
// 5s Harbor poll.
func TestStoredRecordIsCompressed(t *testing.T) {
	mr, s, _ := newTestStore(t)
	ctx := context.Background()
	key := testKey()
	require.NoError(t, s.Create(ctx, job.ScanJob{Key: key, Status: job.Queued}))

	report := bigReport(2000)
	require.NoError(t, s.Finish(ctx, key, report))

	stored, err := mr.Get("test.ns:scan-job:" + key.String())
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix([]byte(stored), gzipMagic), "record must be stored gzipped")

	raw, err := json.Marshal(job.ScanJob{Key: key, Status: job.Finished, Report: report})
	require.NoError(t, err)
	t.Logf("raw=%d bytes stored=%d bytes ratio=%.1fx", len(raw), len(stored), float64(len(raw))/float64(len(stored)))
	assert.Less(t, len(stored), len(raw)/4, "repetitive SPDX must compress by at least 4x")
}

// TestGetReadsPlaintextWrittenByOlderBuild covers the rolling restart: records
// written before compression existed are still in Redis under their TTL, and a
// replica on the new build must serve them rather than 500.
func TestGetReadsPlaintextWrittenByOlderBuild(t *testing.T) {
	mr, s, _ := newTestStore(t)
	key := testKey()

	plaintext, err := json.Marshal(job.ScanJob{
		Key:    key,
		Status: job.Finished,
		Report: json.RawMessage(`{"media_type":"application/spdx+json"}`),
	})
	require.NoError(t, err)
	require.NoError(t, mr.Set("test.ns:scan-job:"+key.String(), string(plaintext)))

	got, err := s.Get(context.Background(), key)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, job.Finished, got.Status)
}

func TestGetMissingReturnsNil(t *testing.T) {
	_, s, _ := newTestStore(t)
	got, err := s.Get(context.Background(), testKey())
	require.NoError(t, err)
	assert.Nil(t, got)
}

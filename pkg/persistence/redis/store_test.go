package redis

import (
	"bytes"
	"compress/gzip"
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

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/etc"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/http/api"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/job"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/persistence"
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

// TestFailIfQueuedOnlyClaimsQueuedRecords pins the enqueue-cleanup contract: a
// dispatch "failure" whose RPUSH actually landed races the worker, and the
// cleanup must never overwrite a record the worker has moved past Queued —
// that would report a completed scan as Failed and discard its report.
func TestFailIfQueuedOnlyClaimsQueuedRecords(t *testing.T) {
	_, s, _ := newTestStore(t)
	ctx := context.Background()

	t.Run("still queued: claimed as failed", func(t *testing.T) {
		key := job.ScanJobKey{ID: "q1", MIMEType: api.MimeTypeSecuritySBOMReport, MediaType: api.MediaTypeSPDX}
		require.NoError(t, s.Create(ctx, job.ScanJob{Key: key, Status: job.Queued}))
		require.NoError(t, s.FailIfQueued(ctx, key, "could not be queued"))
		got, err := s.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, job.Failed, got.Status)
		assert.Contains(t, got.Error, "could not be queued")
	})

	t.Run("worker already finished: left untouched", func(t *testing.T) {
		key := job.ScanJobKey{ID: "f1", MIMEType: api.MimeTypeSecuritySBOMReport, MediaType: api.MediaTypeSPDX}
		report := json.RawMessage(`{"media_type":"application/spdx+json","sbom":{}}`)
		require.NoError(t, s.Create(ctx, job.ScanJob{Key: key, Status: job.Queued}))
		require.NoError(t, s.Finish(ctx, key, report))
		require.NoError(t, s.FailIfQueued(ctx, key, "could not be queued"))
		got, err := s.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, job.Finished, got.Status, "a terminal record must never be overwritten by enqueue cleanup")
		assert.JSONEq(t, string(report), string(got.Report))
	})

	t.Run("worker already running: left untouched", func(t *testing.T) {
		key := job.ScanJobKey{ID: "p1", MIMEType: api.MimeTypeSecuritySBOMReport, MediaType: api.MediaTypeSPDX}
		require.NoError(t, s.Create(ctx, job.ScanJob{Key: key, Status: job.Queued}))
		require.NoError(t, s.UpdateStatus(ctx, key, job.Pending))
		require.NoError(t, s.FailIfQueued(ctx, key, "could not be queued"))
		got, err := s.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, job.Pending, got.Status)
	})

	t.Run("missing record: ErrJobNotFound", func(t *testing.T) {
		key := job.ScanJobKey{ID: "missing", MIMEType: api.MimeTypeSecuritySBOMReport, MediaType: api.MediaTypeSPDX}
		err := s.FailIfQueued(ctx, key, "could not be queued")
		require.ErrorIs(t, err, persistence.ErrJobNotFound)
	})
}

// TestFinishFailsOnExpiredKey keeps the SetXX guarantee after the Get was
// dropped: a job whose TTL elapsed during a long scan must not be resurrected as
// a record Harbor would then poll forever.
func TestFinishFailsOnExpiredKey(t *testing.T) {
	mr, s, _ := newTestStore(t)
	key := testKey()
	// Create it first, then age it out: otherwise the test passes even if TTL
	// handling and SetXX are both broken, because the key never existed.
	require.NoError(t, s.Create(context.Background(), job.ScanJob{Key: key, Status: job.Queued}))
	require.NoError(t, s.Finish(context.Background(), key, json.RawMessage(`{"live":true}`)),
		"sanity: the write must succeed while the key is alive")

	mr.FastForward(2 * time.Hour)

	err := s.Finish(context.Background(), key, json.RawMessage(`{}`))
	require.ErrorIs(t, err, persistence.ErrJobNotFound)

	got, err := s.Get(context.Background(), key)
	require.NoError(t, err)
	assert.Nil(t, got, "an expired job must not be resurrected by the terminal write")
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

// TestDecodeRejectsADecompressionBomb bounds what one record may expand to on a
// report poll. SBOM content derives from a scanned image, so it is
// attacker-influenced, and gzip on repetitive JSON reaches ratios in the tens: a
// small Redis value can otherwise turn into a large allocation on every poll.
func TestDecodeRejectsADecompressionBomb(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	// Highly compressible, well past the limit.
	chunk := bytes.Repeat([]byte("A"), 1<<20)
	for written := 0; written <= maxDecodedBytes; written += len(chunk) {
		_, err := zw.Write(chunk)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	require.Less(t, buf.Len(), 1<<20, "the bomb must be small on the wire, or it is not a bomb")

	_, err := decode(buf.Bytes())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expands beyond")
}

// TestEncodeRejectsAnOversizeRecord keeps the bound symmetric: without it an
// oversize report would be written successfully and then be unreadable, failing
// at poll time instead of at scan time.
func TestEncodeRejectsAnOversizeRecord(t *testing.T) {
	_, err := encode(job.ScanJob{
		Key:    testKey(),
		Status: job.Finished,
		Report: json.RawMessage(`"` + strings.Repeat("x", maxDecodedBytes+16) + `"`),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "over the")
}

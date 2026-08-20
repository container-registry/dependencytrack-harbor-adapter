package redis

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"

	"golang.org/x/xerrors"

	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/job"
	"github.com/container-registry/dependencytrack-harbor-adapter/pkg/metrics"
)

// The record is stored gzipped because it is almost entirely the SPDX document,
// and SPDX is highly repetitive JSON: a golang-image SBOM measured 5.5 MB raw.
// Redis strings are binary-safe, so the compressed bytes go in as-is.
//
// decode sniffs the gzip magic instead of assuming, so a record written by the
// previous plaintext build (still live during a rolling restart, or sitting on a
// list across an upgrade) is still readable rather than a hard cutover.
var gzipMagic = []byte{0x1f, 0x8b}

// maxDecodedBytes bounds what one record may expand to. gzip on repetitive JSON
// reaches ratios in the tens (measured 7.2x on a real alpine envelope, 26.5x on
// synthetic SPDX), so a small Redis value can expand into a large allocation on
// every report poll. The SBOM content is derived from a scanned image, which is
// attacker-influenced, and Redis may be shared. 64 MiB is an order of magnitude
// above the largest report measured (~5.5 MB for a golang image) and is a bomb
// guard, not a working limit. Enforced on write too, so an oversized report
// fails at scan time with a clear cause instead of at poll time.
const maxDecodedBytes = 64 << 20

func encode(scanJob job.ScanJob) ([]byte, error) {
	raw, err := json.Marshal(scanJob)
	if err != nil {
		return nil, xerrors.Errorf("marshaling scan job: %w", err)
	}
	if len(raw) > maxDecodedBytes {
		return nil, xerrors.Errorf("scan job (%s) is %d bytes, over the %d limit",
			scanJob.Key.String(), len(raw), maxDecodedBytes)
	}

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err = zw.Write(raw); err != nil {
		return nil, xerrors.Errorf("compressing scan job: %w", err)
	}
	if err = zw.Close(); err != nil {
		return nil, xerrors.Errorf("compressing scan job: %w", err)
	}

	if len(scanJob.Report) > 0 {
		metrics.ReportBytes.Observe(float64(buf.Len()))
	}
	return buf.Bytes(), nil
}

func decode(stored []byte) (*job.ScanJob, error) {
	raw := stored
	if bytes.HasPrefix(stored, gzipMagic) {
		zr, err := gzip.NewReader(bytes.NewReader(stored))
		if err != nil {
			return nil, xerrors.Errorf("decompressing scan job: %w", err)
		}
		defer zr.Close()
		// Read one byte past the limit so hitting it is distinguishable from a
		// record that happens to be exactly maxDecodedBytes long.
		if raw, err = io.ReadAll(io.LimitReader(zr, maxDecodedBytes+1)); err != nil {
			return nil, xerrors.Errorf("decompressing scan job: %w", err)
		}
		if len(raw) > maxDecodedBytes {
			return nil, xerrors.Errorf("stored scan job expands beyond the %d byte limit", maxDecodedBytes)
		}
	}

	var scanJob job.ScanJob
	if err := json.Unmarshal(raw, &scanJob); err != nil {
		return nil, xerrors.Errorf("unmarshaling scan job: %w", err)
	}
	return &scanJob, nil
}

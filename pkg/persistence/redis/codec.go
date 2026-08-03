package redis

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"

	"golang.org/x/xerrors"

	"github.com/container-registry/waybill-harbor-adapter/pkg/job"
	"github.com/container-registry/waybill-harbor-adapter/pkg/metrics"
)

// The record is stored gzipped because it is almost entirely the SPDX document,
// and SPDX is highly repetitive JSON: a golang-image SBOM measured 5.5 MB raw.
// Redis strings are binary-safe, so the compressed bytes go in as-is.
//
// decode sniffs the gzip magic instead of assuming, so a record written by the
// previous plaintext build (still live during a rolling restart, or sitting on a
// list across an upgrade) is still readable rather than a hard cutover.
var gzipMagic = []byte{0x1f, 0x8b}

func encode(scanJob job.ScanJob) ([]byte, error) {
	raw, err := json.Marshal(scanJob)
	if err != nil {
		return nil, xerrors.Errorf("marshaling scan job: %w", err)
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
		if raw, err = io.ReadAll(zr); err != nil {
			return nil, xerrors.Errorf("decompressing scan job: %w", err)
		}
	}

	var scanJob job.ScanJob
	if err := json.Unmarshal(raw, &scanJob); err != nil {
		return nil, xerrors.Errorf("unmarshaling scan job: %w", err)
	}
	return &scanJob, nil
}

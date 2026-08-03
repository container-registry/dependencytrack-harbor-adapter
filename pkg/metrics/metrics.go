// Package metrics holds the adapter's own Prometheus collectors. The /metrics
// endpoint previously served nothing but Go runtime stats, which for a scanner
// that takes minutes per artifact answers none of the questions an operator has:
// how many scans are running, how long they take, how many fail, and whether the
// failures are the scanner's fault or the registry registration's.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const namespace = "harbor_scanner_waybill"

// Category label values that do not come from waybill.ErrorCategory.
const (
	// CategoryNone is the category on a successful scan. Prometheus wants a
	// consistent label set across a metric, so success carries an explicit
	// value rather than an empty string.
	CategoryNone = "none"
	// CategoryAdapter is a failure the adapter raised itself. Kept apart from
	// WaybillExec so an adapter bug is not blamed on the scanner.
	CategoryAdapter = "Adapter"
	// CategoryExpired is a job whose store record was gone by the time it ran:
	// it waited longer than the scan job TTL. That is a capacity signal —
	// raise concurrency, add replicas, or raise the TTL — not a failure of
	// either the adapter or waybill, so it does not pollute either count.
	CategoryExpired = "Expired"
)

// Outcome label values for ScansTotal / ScanDurationSeconds.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

var (
	// ScansTotal is the one that matters operationally: category comes from
	// waybill.ErrorCategory, so a spike in RegistryPullAuth points at the robot
	// account and a spike in WaybillExec points at the scanner itself. Both
	// labels are bounded enums, so cardinality is fixed.
	ScansTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "scans_total",
		Help:      "Scan jobs that reached a terminal state, by outcome and failure category.",
	}, []string{"outcome", "category"})

	// ScanDurationSeconds buckets reach 1800s because Harbor abandons a report
	// poll after 30 minutes: anything in the top bucket is work the adapter did
	// that Harbor will never collect.
	ScanDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "scan_duration_seconds",
		Help:      "Wall-clock time from picking a job up to writing its terminal state.",
		Buckets:   []float64{1, 5, 10, 30, 60, 120, 300, 600, 900, 1800},
	}, []string{"outcome"})

	// QueueWaitSeconds is what exposes an under-provisioned worker pool. The
	// scan itself can be fast while Harbor still times out, because the job sat
	// in the list behind others; only the wait shows that.
	QueueWaitSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "queue_wait_seconds",
		Help:      "Time a job spent queued before a worker picked it up.",
		Buckets:   []float64{0.1, 1, 5, 15, 60, 300, 900, 1800},
	})

	ScansInFlight = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "scans_in_flight",
		Help:      "Scan jobs currently executing in this process.",
	})

	EnqueuedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "enqueued_total",
		Help:      "Scan jobs accepted and placed on the queue.",
	})

	EnqueueFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "enqueue_failures_total",
		Help:      "Scan requests that could not be queued.",
	})

	// ReportBytes is measured on the stored (compressed) envelope, so it tracks
	// what actually lands in Redis rather than what waybill emitted.
	ReportBytes = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "report_stored_bytes",
		Help:      "Size of the stored, compressed report envelope.",
		Buckets:   prometheus.ExponentialBuckets(1<<14, 4, 8),
	})
)

// ObserveScan records one terminal scan. category is ignored on success.
func ObserveScan(success bool, category string, seconds float64) {
	outcome := OutcomeFailure
	if success {
		outcome = OutcomeSuccess
		category = CategoryNone
	}
	ScansTotal.WithLabelValues(outcome, category).Inc()
	ScanDurationSeconds.WithLabelValues(outcome).Observe(seconds)
}

// MustRegisterQueueDepth wires a queue-depth gauge to a caller-supplied sampler.
// The sampler runs on the scrape goroutine, so it must be bounded; it should
// return NaN rather than 0 when the depth cannot be read, so a broken Redis
// reads as "unknown" on the dashboard instead of "empty queue".
func MustRegisterQueueDepth(sample func() float64) {
	prometheus.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "queue_depth",
		Help:      "Scan jobs waiting on the queue, NaN if it cannot be read.",
	}, sample))
}

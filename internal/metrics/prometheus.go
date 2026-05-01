package metrics

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/hibiken/asynq"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Queue metrics
	queuePending = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "asynq_queue_pending_jobs",
		Help: "Number of pending jobs in Asynq queue",
	}, []string{"queue"})

	queueActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "asynq_queue_active_jobs",
		Help: "Number of active jobs being processed",
	}, []string{"queue"})

	queueDead = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "asynq_queue_dead_jobs",
		Help: "Number of dead jobs (exhausted retries)",
	}, []string{"queue"})

	// Scan metrics
	scansTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aspm_scans_total",
		Help: "Total number of scans",
	})

	scansRunning = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aspm_scans_running",
		Help: "Number of scans currently running",
	})

	scansFailed = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aspm_scans_failed",
		Help: "Number of failed scans",
	})

	// Finding metrics
	findingsTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aspm_findings_total",
		Help: "Total number of findings by severity",
	}, []string{"severity"})

	// Job processing metrics
	jobProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "asynq_jobs_processed_total",
		Help: "Total number of jobs processed",
	}, []string{"type", "status"})

	jobDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "asynq_job_duration_seconds",
		Help:    "Job processing duration in seconds",
		Buckets: prometheus.ExponentialBuckets(1, 2, 10),
	}, []string{"type"})
)

// StartPrometheusServer starts the Prometheus metrics endpoint
func StartPrometheusServer(addr string) {
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		slog.Info("Prometheus metrics server starting", "addr", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			slog.Error("Prometheus metrics server failed", "err", err)
		}
	}()
}

// StartQueueMetricsCollector starts periodic collection of queue metrics
func StartQueueMetricsCollector(ctx context.Context, inspector *asynq.Inspector, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Collect immediately
		collectQueueMetrics(inspector)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				collectQueueMetrics(inspector)
			}
		}
	}()
}

func collectQueueMetrics(inspector *asynq.Inspector) {
	queues, err := inspector.Queues()
	if err != nil {
		slog.Warn("failed to get queues", "err", err)
		return
	}

	for _, q := range queues {
		info, err := inspector.GetQueueInfo(q)
		if err != nil {
			slog.Warn("failed to get queue info", "queue", q, "err", err)
			continue
		}

		queuePending.WithLabelValues(q).Set(float64(info.Pending))
		queueActive.WithLabelValues(q).Set(float64(info.Active))
		queueDead.WithLabelValues(q).Set(float64(info.Archived))
	}
}

// StartDBMetricsCollector starts periodic collection of DB metrics
func StartDBMetricsCollector(ctx context.Context, getMetrics func() (int, int, int, map[string]int, error), interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Collect immediately
		collectDBMetrics(getMetrics)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				collectDBMetrics(getMetrics)
			}
		}
	}()
}

func collectDBMetrics(getMetrics func() (int, int, int, map[string]int, error)) {
	total, running, failed, findings, err := getMetrics()
	if err != nil {
		slog.Warn("failed to get DB metrics", "err", err)
		return
	}

	scansTotal.Set(float64(total))
	scansRunning.Set(float64(running))
	scansFailed.Set(float64(failed))

	for severity, count := range findings {
		findingsTotal.WithLabelValues(severity).Set(float64(count))
	}
}



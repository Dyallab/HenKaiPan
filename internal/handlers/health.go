package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"syscall"
	"time"
)

type HealthCheck struct {
	Status    string         `json:"status"`
	Checks    HealthChecks   `json:"checks"`
	Timestamp string         `json:"timestamp"`
}

type HealthChecks struct {
	Database HealthCheckResult `json:"database"`
	Redis    HealthCheckResult `json:"redis"`
	Worker   HealthCheckResult `json:"worker"`
	Disk     HealthCheckResult `json:"disk"`
}

type HealthCheckResult struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (h *Handler) GetHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	checks := HealthChecks{}
	overallStatus := "ok"

	dbStart := time.Now()
	err := h.store.Health.CheckDB(ctx)
	dbLatency := time.Since(dbStart)
	if err != nil {
		checks.Database = HealthCheckResult{
			Status: "down",
			Error:  err.Error(),
		}
		overallStatus = "down"
	} else {
		checks.Database = HealthCheckResult{
			Status:  "ok",
			Message: formatLatency(dbLatency),
		}
	}

	redisStart := time.Now()
	err = h.store.Health.CheckRedis(ctx)
	redisLatency := time.Since(redisStart)
	if err != nil {
		checks.Redis = HealthCheckResult{
			Status: "down",
			Error:  err.Error(),
		}
		if overallStatus != "down" {
			overallStatus = "degraded"
		}
	} else {
		checks.Redis = HealthCheckResult{
			Status:  "ok",
			Message: formatLatency(redisLatency),
		}
	}

	workerActive, err := h.store.Health.CheckWorker(ctx)
	if err != nil {
		checks.Worker = HealthCheckResult{
			Status: "unknown",
			Error:  err.Error(),
		}
		if overallStatus == "ok" {
			overallStatus = "degraded"
		}
	} else if !workerActive {
		checks.Worker = HealthCheckResult{
			Status:  "warning",
			Message: "No recent job activity detected",
		}
		if overallStatus == "ok" {
			overallStatus = "degraded"
		}
	} else {
		checks.Worker = HealthCheckResult{
			Status: "ok",
		}
	}

	diskFree, diskTotal, err := getDiskUsage("/")
	if err != nil {
		checks.Disk = HealthCheckResult{
			Status: "unknown",
			Error:  err.Error(),
		}
	} else {
		usagePercent := float64(diskTotal-diskFree) / float64(diskTotal) * 100
		if usagePercent > 90 {
			checks.Disk = HealthCheckResult{
				Status:  "warning",
				Message: formatDiskUsage(diskFree, diskTotal),
			}
			if overallStatus == "ok" {
				overallStatus = "degraded"
			}
		} else {
			checks.Disk = HealthCheckResult{
				Status:  "ok",
				Message: formatDiskUsage(diskFree, diskTotal),
			}
		}
	}

	response := HealthCheck{
		Status:    overallStatus,
		Checks:    checks,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	writeJSON(w, http.StatusOK, response)
}

func formatLatency(d time.Duration) string {
	if d < time.Millisecond {
		return d.String()
	}
	return d.Round(time.Millisecond).String()
}

func formatDiskUsage(free, total uint64) string {
	used := total - free
	return formatBytes(used) + " / " + formatBytes(total) + " used"
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return json.Number(strconv.FormatUint(b, 10)).String() + " B"
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return string(json.Number(strconv.FormatUint(b/div, 10))) + " " + "KMGTPE"[exp:exp+1] + "B"
}

func getDiskUsage(path string) (free, total uint64, err error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, err
	}
	total = stat.Blocks * uint64(stat.Bsize)
	free = stat.Bavail * uint64(stat.Bsize)
	return free, total, nil
}

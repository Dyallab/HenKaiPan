package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type versionCheckResponse struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	LatestURL       string `json:"latest_url"`
	CheckedAt       string `json:"checked_at"`
	Error           string `json:"error,omitempty"`
}

var versionCheckCache struct {
	mu       sync.RWMutex
	result   *versionCheckResponse
	cachedAt time.Time
	ttl      time.Duration
}

func init() {
	versionCheckCache.ttl = 1 * time.Hour
}

func (h *Handler) GetVersionCheck(w http.ResponseWriter, r *http.Request) {
	if Version == "dev" {
		writeJSON(w, http.StatusOK, versionCheckResponse{
			CurrentVersion:  Version,
			UpdateAvailable: false,
			CheckedAt:       time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	versionCheckCache.mu.RLock()
	cached := versionCheckCache.result
	cachedAt := versionCheckCache.cachedAt
	versionCheckCache.mu.RUnlock()

	if cached != nil && time.Since(cachedAt) < versionCheckCache.ttl {
		cached.CurrentVersion = Version
		writeJSON(w, http.StatusOK, cached)
		return
	}

	result := fetchLatestRelease(Version)
	result.CurrentVersion = Version

	versionCheckCache.mu.Lock()
	versionCheckCache.result = result
	versionCheckCache.cachedAt = time.Now()
	versionCheckCache.mu.Unlock()

	writeJSON(w, http.StatusOK, result)
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

func fetchLatestRelease(currentVersion string) *versionCheckResponse {
	resp, err := http.Get("https://api.github.com/repos/Dyallab/HenKaiPan-self-hosted/releases/latest")
	if err != nil {
		slog.Warn("version check: github api request failed", "err", err)
		return &versionCheckResponse{
			UpdateAvailable: false,
			CheckedAt:       time.Now().UTC().Format(time.RFC3339),
			Error:           "failed to check for updates",
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("version check: github api returned unexpected status", "status", resp.StatusCode)
		return &versionCheckResponse{
			UpdateAvailable: false,
			CheckedAt:       time.Now().UTC().Format(time.RFC3339),
			Error:           "failed to check for updates",
		}
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		slog.Warn("version check: failed to decode github response", "err", err)
		return &versionCheckResponse{
			UpdateAvailable: false,
			CheckedAt:       time.Now().UTC().Format(time.RFC3339),
			Error:           "failed to check for updates",
		}
	}

	updateAvailable := semverGreater(release.TagName, currentVersion)

	return &versionCheckResponse{
		LatestVersion:   release.TagName,
		UpdateAvailable: updateAvailable,
		LatestURL:       release.HTMLURL,
		CheckedAt:       time.Now().UTC().Format(time.RFC3339),
	}
}

func semverGreater(a, b string) bool {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")

	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")

	for len(ap) < 3 {
		ap = append(ap, "0")
	}
	for len(bp) < 3 {
		bp = append(bp, "0")
	}

	for i := 0; i < 3; i++ {
		ai, errA := strconv.Atoi(ap[i])
		bi, errB := strconv.Atoi(bp[i])
		if errA != nil || errB != nil {
			return false
		}
		if ai > bi {
			return true
		}
		if ai < bi {
			return false
		}
	}
	return false
}

package handlers

import (
	"log/slog"
	"net/http"

	"aspm/internal/auth"
	"aspm/internal/pagination"
	"aspm/internal/repository"
)

// ListThreatExposures returns inventory↔advisory correlation hits joined
// with their advisory columns (threat-intel MVP, issue #64). It clones
// ListVulnerabilities: same pagination defaults (100/200), same
// {exposures, total} envelope shape, sort passthrough (the whitelist lives
// in the repository layer).
//
// Query params: project_id, kev, match_status, inventory_status, q,
// page, limit, sort.
//
// ExposureFilter carries no user field (the listing is project-scoped), so
// datascope scoping is enforced at the edge: non-admin callers must name a
// project_id, while admins may list across projects.
func (h *Handler) ListThreatExposures(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	if claims == nil {
		writeError(w, r, http.StatusUnauthorized, "authentication required")
		return
	}

	q := r.URL.Query()
	p := pagination.FromQueryWithDefaults(q, 100, 200)

	projectID := q.Get("project_id")
	if claims.Role != "admin" && projectID == "" {
		writeError(w, r, http.StatusForbidden, "project_id is required for non-admin users")
		return
	}

	kevParam := q.Get("kev")
	rows, total, err := h.store.Threats.ListExposures(r.Context(), repository.ExposureFilter{
		ProjectID:       projectID,
		KEVOnly:         kevParam == "true" || kevParam == "1",
		MatchStatus:     q.Get("match_status"),
		InventoryStatus: q.Get("inventory_status"),
		Q:               q.Get("q"),
		Page:            p.Page,
		Limit:           p.Limit,
		Sort:            q.Get("sort"),
	})
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to list threat exposures", "error", err)
		writeError(w, r, http.StatusInternalServerError, "failed to list threat exposures")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exposures": rows, "total": total})
}

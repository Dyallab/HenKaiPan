package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"aspm/internal/auth"
	"aspm/internal/httperrors"
)

type ownershipStore interface {
	CheckProjectOwnership(ctx context.Context, userID, projectID string) (bool, error)
	CheckAppOwnership(ctx context.Context, userID, appID string) (bool, error)
	CheckScanOwnership(ctx context.Context, userID, scanID string) (bool, error)
	CheckFindingOwnership(ctx context.Context, userID, findingID string) (bool, error)
	CheckRiskAcceptanceOwnership(ctx context.Context, userID, riskAcceptanceID string) (bool, error)
}

func RequireOwnership(store ownershipStore, resourceType string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.GetClaims(r)
			if claims == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if claims.Role == "admin" {
				next.ServeHTTP(w, r)
				return
			}

			resourceID := extractResourceID(r, resourceType)
			if resourceID == "" {
				writeJSONError(w, http.StatusBadRequest, httperrors.ErrBadRequest, "Resource ID required")
				return
			}

			var owned bool
			var err error

			switch resourceType {
			case "project":
				owned, err = store.CheckProjectOwnership(r.Context(), claims.UserID, resourceID)
			case "app":
				owned, err = store.CheckAppOwnership(r.Context(), claims.UserID, resourceID)
			case "scan":
				owned, err = store.CheckScanOwnership(r.Context(), claims.UserID, resourceID)
			case "finding":
				owned, err = store.CheckFindingOwnership(r.Context(), claims.UserID, resourceID)
			case "risk-acceptance":
				owned, err = store.CheckRiskAcceptanceOwnership(r.Context(), claims.UserID, resourceID)
			default:
				writeJSONError(w, http.StatusBadRequest, httperrors.ErrBadRequest, "Unknown resource type")
				return
			}

			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, httperrors.ErrInternal, "Ownership check failed")
				return
			}

			if !owned {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"code":    code,
		"message": message,
	})
}

func extractResourceID(r *http.Request, resourceType string) string {
	path := r.URL.Path
	parts := strings.Split(path, "/")

	for i, part := range parts {
		if part == resourceType || part == strings.Replace(resourceType, "-", "", -1) {
			if i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}

	if resourceType == "project" {
		for i, part := range parts {
			if part == "projects" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}

	return ""
}

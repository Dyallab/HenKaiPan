package license

import (
	"encoding/json"
	"net/http"

	"aspm/internal/auth"
)

type licenseError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Feature string `json:"feature"`
}

func (s *Service) RequireFeature(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.HasFeature(feature) {
				next.ServeHTTP(w, r)
				return
			}

			if r.Method == http.MethodGet {
				claims := auth.GetClaims(r)
				if claims != nil && claims.Role == "admin" {
					next.ServeHTTP(w, r)
					return
				}
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			json.NewEncoder(w).Encode(licenseError{
				Error:   "license_required",
				Message: "This feature requires a paid license key. Contact sales@dyallab.com.ar to upgrade.",
				Feature: feature,
			})
		})
	}
}

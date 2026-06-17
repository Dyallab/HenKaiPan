package middleware

import (
	"log/slog"
	"net/http"

	"aspm/internal/auth"
	"aspm/internal/repository"
)

// RequireValidTokenVersion returns middleware that checks the token_version claim
// in the JWT against the current token_version stored in the database.
// If the token's version is stale (password was changed after token issuance),
// the request is rejected with 401 Unauthorized.
func RequireValidTokenVersion(store repository.Stores) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.GetClaims(r)
			if claims == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			currentVersion, err := store.Users.GetTokenVersion(r.Context(), claims.UserID)
			if err != nil {
				slog.ErrorContext(r.Context(), "token version check: db error",
					"user_id", claims.UserID, "err", err)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if claims.TokenVersion < currentVersion {
				slog.WarnContext(r.Context(), "token version stale — session invalidated",
					"user_id", claims.UserID,
					"token_version", claims.TokenVersion,
					"current_version", currentVersion)
				http.Error(w, "session expired, please log in again", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

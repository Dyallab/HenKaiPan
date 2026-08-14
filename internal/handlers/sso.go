package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"aspm/internal/auth"
	"aspm/internal/models"
	"aspm/internal/repository"
	"aspm/internal/sso"

	"github.com/jackc/pgx/v5"
)

// ssoStateCookie is the cookie name holding the OIDC state nonce.
const ssoStateCookie = "aspm_sso_state"

// SSOLogin redirects the browser to the OIDC provider's authorization endpoint.
func (h *Handler) SSOLogin(w http.ResponseWriter, r *http.Request) {
	if !h.ssoEnabled || h.ssoProvider == nil {
		writeError(w, r, http.StatusNotFound, "sso not configured")
		return
	}

	nonce, err := sso.GenerateState()
	if err != nil {
		h.writeInternal(w, r, err, "failed to generate SSO state")
		return
	}

	signed, err := auth.SignState(nonce.State)
	if err != nil {
		h.writeInternal(w, r, err, "failed to sign SSO state")
		return
	}

	// Store signed state in a short-lived cookie (HttpOnly, 5min).
	cookie := &http.Cookie{
		Name:     ssoStateCookie,
		Value:    signed,
		Path:     "/",
		MaxAge:   int(5 * time.Minute / time.Second),
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: parseSameSiteMode(h.cookieSameSite),
	}
	if h.cookieDomain != "" {
		cookie.Domain = h.cookieDomain
	}
	http.SetCookie(w, cookie)

	redirectURL := h.ssoProvider.AuthURL(nonce.State)
	slog.InfoContext(r.Context(), "sso login initiated", "state_len", len(nonce.State))
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// SSOCallback handles the OIDC provider redirect back, exchanges the code for
// tokens, verifies the ID token, and links or creates the local user.
func (h *Handler) SSOCallback(w http.ResponseWriter, r *http.Request) {
	if !h.ssoEnabled || h.ssoProvider == nil {
		writeError(w, r, http.StatusNotFound, "sso not configured")
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		writeError(w, r, http.StatusBadRequest, "missing code or state parameter")
		return
	}

	// Verify the callback state against the signed cookie set in SSOLogin.
	cookie, err := r.Cookie(ssoStateCookie)
	if err != nil || cookie.Value == "" {
		writeError(w, r, http.StatusBadRequest, "invalid or expired SSO state")
		return
	}
	cookieState, err := auth.VerifyState(cookie.Value)
	if err != nil || cookieState != state {
		writeError(w, r, http.StatusBadRequest, "invalid or expired SSO state")
		return
	}
	// Clear the state cookie.
	http.SetCookie(w, &http.Cookie{
		Name: ssoStateCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: h.cookieSecure, SameSite: parseSameSiteMode(h.cookieSameSite),
	})

	claims, err := h.ssoProvider.ExchangeAndVerify(r.Context(), code)
	if err != nil {
		slog.WarnContext(r.Context(), "sso token exchange failed", "error", err)
		http.Redirect(w, r, "/login?error=sso_failed", http.StatusFound)
		return
	}

	if claims.Email == "" {
		slog.WarnContext(r.Context(), "sso callback: no email in claims", "subject", claims.Subject)
		http.Redirect(w, r, "/login?error=sso_no_email", http.StatusFound)
		return
	}

	provider := h.ssoProvider.Issuer()
	user, err := h.resolveSSOUser(r.Context(), provider, claims)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso user resolution failed", "email", claims.Email, "error", err)
		http.Redirect(w, r, "/login?error=sso_error", http.StatusFound)
		return
	}

	if err := h.store.Users.UpdateLastLogin(r.Context(), user.ID); err != nil {
		slog.ErrorContext(r.Context(), "sso: update last_login failed", "user_id", user.ID, "error", err)
	}

	tokenVersion, err := h.store.Users.GetTokenVersion(r.Context(), user.ID)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso: get token version failed", "user_id", user.ID, "error", err)
		http.Redirect(w, r, "/login?error=sso_error", http.StatusFound)
		return
	}

	jwtToken, err := auth.IssueToken(user.Username, user.Role, user.ID, tokenVersion)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso: issue token failed", "error", err)
		http.Redirect(w, r, "/login?error=sso_error", http.StatusFound)
		return
	}

	auth.SetAuthCookie(w, jwtToken, h.cookieSecure, h.cookieDomain, h.cookieSameSite)
	slog.InfoContext(r.Context(), "sso login success", "user_id", user.ID, "username", user.Username, "email", claims.Email)
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// resolveSSOUser finds or creates the local user for the given OIDC claims.
// Order: (1) match by (provider, subject), (2) match by email + link,
// (3) create new. Linking is restricted to an existing account whose verified
// email matches the claim; a username collision is returned as an error rather
// than silently linking the identity to an unrelated account.
// On every resolution the role is re-evaluated from the IdP group claim and
// synced if it changed (so group-membership changes take effect on next login).
func (h *Handler) resolveSSOUser(ctx context.Context, provider string, claims *sso.Claims) (*models.User, error) {
	// 1. Already linked?
	user, err := h.store.Users.GetUserBySSOIdentity(ctx, provider, claims.Subject)
	if err == nil {
		return h.syncSSORole(ctx, user, claims)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get user by sso identity: %w", err)
	}

	// 2. Match by email, then link.
	user, err = h.store.Users.GetUserByEmail(ctx, claims.Email)
	if err == nil {
		if err := h.store.Users.LinkSSOIdentity(ctx, user.ID, provider, claims.Subject); err != nil {
			return nil, fmt.Errorf("link sso identity: %w", err)
		}
		user.SSOProvider = &provider
		user.SSOSubject = &claims.Subject
		slog.InfoContext(ctx, "sso identity linked to existing user", "user_id", user.ID, "email", claims.Email)
		return h.syncSSORole(ctx, user, claims)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	// 3. Create new user.
	role := h.ssoProvider.ResolveRole(claims)
	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}

	user, err = h.store.Users.Create(ctx, repository.UserCreate{
		Username:     username,
		Email:        claims.Email,
		PasswordHash: "", // SSO-only users have no password
		Role:         role,
	})
	if err != nil {
		return nil, fmt.Errorf("create sso user: %w", err)
	}
	if err := h.store.Users.LinkSSOIdentity(ctx, user.ID, provider, claims.Subject); err != nil {
		return nil, fmt.Errorf("link sso identity (new user): %w", err)
	}
	user.SSOProvider = &provider
	user.SSOSubject = &claims.Subject
	slog.InfoContext(ctx, "sso user created", "user_id", user.ID, "email", claims.Email, "role", role)
	return user, nil
}

// syncSSORole re-evaluates the role from the IdP group claim and updates the
// user's role if it changed (IdP group membership is the source of truth for
// SSO users). Keeps the DB in sync without clobbering manually-set roles that
// aren't SSO-linked — this is only called for SSO-linked users.
func (h *Handler) syncSSORole(ctx context.Context, user *models.User, claims *sso.Claims) (*models.User, error) {
	want := h.ssoProvider.ResolveRole(claims)
	if user.Role != want {
		updated, err := h.store.Users.Update(ctx, user.ID, repository.UserUpdate{Role: &want})
		if err != nil {
			return nil, fmt.Errorf("sync sso role: %w", err)
		}
		slog.InfoContext(ctx, "sso role synced", "user_id", user.ID, "username", user.Username, "old_role", user.Role, "new_role", want)
		return updated, nil
	}
	return user, nil
}

func parseSameSiteMode(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

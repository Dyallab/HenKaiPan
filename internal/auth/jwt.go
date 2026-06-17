package auth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secret string

const authCookieName = "aspm_token"

// SetSecret must be called at startup with the value from config.
// Calling IssueToken or Parse before SetSecret will panic.
func SetSecret(s string) {
	if s == "" {
		panic("JWT secret cannot be empty")
	}
	secret = s
}

type ctxKey string

const claimsKey ctxKey = "claims"

type Claims struct {
	Sub          string `json:"sub"`
	Role         string `json:"role"`
	UserID       string `json:"user_id"`
	TokenVersion int    `json:"tok_ver"`
	Exp          int64  `json:"exp"`
}

func IssueToken(username, role, userID string, tokenVersion int) (string, error) {
	if secret == "" {
		panic("JWT secret not initialized. Call SetSecret() before IssueToken()")
	}
	secret := []byte(jwtSecret())
	claims := jwt.MapClaims{
		"sub":     username,
		"role":    role,
		"user_id": userID,
		"tok_ver": tokenVersion,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := parseToken(r)
		if err != nil {
			slog.WarnContext(r.Context(), "JWT middleware failed", "error", err.Error(), "path", r.URL.Path)
			// Debug: log what we found
			if cookie, cerr := r.Cookie(authCookieName); cerr == nil {
				slog.DebugContext(r.Context(), "cookie found but parsing failed", "cookie_len", len(cookie.Value))
			} else {
				slog.DebugContext(r.Context(), "no auth cookie found", "cookie_error", cerr.Error())
			}
			if auth := r.Header.Get("Authorization"); auth != "" {
				slog.DebugContext(r.Context(), "Authorization header found", "header_len", len(auth))
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func SetAuthCookie(w http.ResponseWriter, token string, secure bool, domain, sameSite string) {
	sameSiteMode := parseSameSite(sameSite)
	slog.Debug("setting auth cookie", "token_len", len(token), "secure", secure, "domain", domain, "samesite", sameSiteMode)
	cookie := &http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int((24 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSiteMode,
	}
	if domain != "" {
		cookie.Domain = domain
	}
	http.SetCookie(w, cookie)
}

func ClearAuthCookie(w http.ResponseWriter, secure bool, domain, sameSite string) {
	sameSiteMode := parseSameSite(sameSite)
	cookie := &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSiteMode,
	}
	if domain != "" {
		cookie.Domain = domain
	}
	http.SetCookie(w, cookie)
}

func parseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

// RequireRole returns middleware that allows only the given roles.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r)
			if claims == nil || !allowed[claims.Role] {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func GetClaims(r *http.Request) *Claims {
	v, ok := r.Context().Value(claimsKey).(jwt.MapClaims)
	if !ok {
		return nil
	}
	c := &Claims{}
	if s, ok := v["sub"].(string); ok {
		c.Sub = s
	}
	if s, ok := v["role"].(string); ok {
		c.Role = s
	}
	if s, ok := v["user_id"].(string); ok {
		c.UserID = s
	}
	if f, ok := v["tok_ver"].(float64); ok {
		c.TokenVersion = int(f)
	}
	return c
}

func parseToken(r *http.Request) (jwt.MapClaims, error) {
	if secret == "" {
		panic("JWT secret not initialized. Call SetSecret() before parsing tokens")
	}
	tokenStr := strings.TrimSpace(tokenFromRequest(r))
	if tokenStr == "" {
		slog.Debug("no token found in request")
		return nil, jwt.ErrSignatureInvalid
	}
	slog.Debug("parsing JWT", "token_len", len(tokenStr))
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			slog.Warn("invalid token method", "method", t.Method.Alg())
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(jwtSecret()), nil
	}, jwt.WithExpirationRequired())
	if err != nil {
		slog.Warn("JWT parse error", "error", err.Error())
		return nil, err
	}
	if !token.Valid {
		slog.Warn("JWT invalid")
		return nil, jwt.ErrSignatureInvalid
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		slog.Warn("failed to extract claims")
		return nil, jwt.ErrSignatureInvalid
	}
	
	slog.Debug("JWT parsed successfully", "subject", claims["sub"])
	return claims, nil
}

func tokenFromRequest(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if prefix, after, ok := strings.Cut(header, " "); ok && prefix == "Bearer" {
		return after
	}
	if cookie, err := r.Cookie(authCookieName); err == nil {
		return cookie.Value
	}
	return ""
}

func jwtSecret() string { return secret }

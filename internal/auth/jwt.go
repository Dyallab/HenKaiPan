package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secret = "dev-secret"

const authCookieName = "aspm_token"

// SetSecret must be called at startup with the value from config.
func SetSecret(s string) { secret = s }

type ctxKey string

const claimsKey ctxKey = "claims"

type Claims struct {
	Sub    string `json:"sub"`
	Role   string `json:"role"`
	UserID string `json:"user_id"`
	Exp    int64  `json:"exp"`
}

func IssueToken(username, role, userID string) (string, error) {
	secret := []byte(jwtSecret())
	claims := jwt.MapClaims{
		"sub":     username,
		"role":    role,
		"user_id": userID,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := parseToken(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func SetAuthCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int((24 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func ClearAuthCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
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
	return c
}

func parseToken(r *http.Request) (jwt.MapClaims, error) {
	tokenStr := strings.TrimSpace(tokenFromRequest(r))
	if tokenStr == "" {
		return nil, jwt.ErrSignatureInvalid
	}
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(jwtSecret()), nil
	})
	if err != nil || !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, jwt.ErrSignatureInvalid
	}
	return claims, nil
}

func tokenFromRequest(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}
	if cookie, err := r.Cookie(authCookieName); err == nil {
		return cookie.Value
	}
	return ""
}

func jwtSecret() string { return secret }

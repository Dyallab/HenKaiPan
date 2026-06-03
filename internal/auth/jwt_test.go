package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aspm/internal/assert"
	"github.com/golang-jwt/jwt/v5"
)

func TestMain(m *testing.M) {
	SetSecret("test-secret-for-jwt-tests-2026")
	m.Run()
}

func TestIssueToken_ReturnsValidJWT(t *testing.T) {
	token, err := IssueToken("alice", "admin", "usr_001")
	assert.NoError(t, err)
	assert.True(t, token != "")

	parsed, err := jwt.Parse(token, func(tok *jwt.Token) (any, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte("test-secret-for-jwt-tests-2026"), nil
	}, jwt.WithExpirationRequired())
	assert.NoError(t, err)
	assert.True(t, parsed.Valid)

	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, claims["sub"], "alice")
	assert.Equal(t, claims["role"], "admin")
	assert.Equal(t, claims["user_id"], "usr_001")
}

func TestParseToken_CookieAuth(t *testing.T) {
	token, _ := IssueToken("bob", "viewer", "usr_002")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: authCookieName, Value: token})

	claims, err := parseToken(req)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, claims["sub"], "bob")
}

func TestParseToken_BearerAuth(t *testing.T) {
	token, _ := IssueToken("carol", "admin", "usr_003")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	claims, err := parseToken(req)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, claims["role"], "admin")
}

func TestParseToken_NoToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := parseToken(req)
	assert.ErrorIs(t, err, jwt.ErrSignatureInvalid)
}

func TestParseToken_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	_, err := parseToken(req)
	assert.True(t, err != nil)
}

func TestGetClaims_FromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), claimsKey, jwt.MapClaims{
		"sub":     "alice",
		"role":    "admin",
		"user_id": "usr_001",
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)

	claims := GetClaims(req)
	assert.NotNil(t, claims)
	assert.Equal(t, claims.Sub, "alice")
	assert.Equal(t, claims.Role, "admin")
	assert.Equal(t, claims.UserID, "usr_001")
}

func TestGetClaims_NoClaims(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	claims := GetClaims(req)
	assert.Nil(t, claims)
}

func TestGetClaims_WrongContextType(t *testing.T) {
	ctx := context.WithValue(context.Background(), claimsKey, "not-map-claims")
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	claims := GetClaims(req)
	assert.Nil(t, claims)
}

func TestParseSameSite(t *testing.T) {
	tests := []struct {
		input string
		want  http.SameSite
	}{
		{"strict", http.SameSiteStrictMode},
		{"Strict", http.SameSiteStrictMode},
		{"none", http.SameSiteNoneMode},
		{"None", http.SameSiteNoneMode},
		{"lax", http.SameSiteLaxMode},
		{"LAX", http.SameSiteLaxMode},
		{"", http.SameSiteLaxMode},
		{"unknown", http.SameSiteLaxMode},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseSameSite(tc.input)
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestTokenFromRequest_Bearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer my-token-here")
	token := tokenFromRequest(req)
	assert.Equal(t, token, "my-token-here")
}

func TestTokenFromRequest_Cookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: authCookieName, Value: "cookie-token"})
	token := tokenFromRequest(req)
	assert.Equal(t, token, "cookie-token")
}

func TestTokenFromRequest_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	token := tokenFromRequest(req)
	assert.Equal(t, token, "")
}

func TestTokenFromRequest_BearerPrecedence(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer from-header")
	req.AddCookie(&http.Cookie{Name: authCookieName, Value: "from-cookie"})
	token := tokenFromRequest(req)
	assert.Equal(t, token, "from-header") // Bearer should take precedence
}

func TestRequireRole_AllowsCorrectRole(t *testing.T) {
	handler := RequireRole("admin")
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	ctx := context.WithValue(context.Background(), claimsKey, jwt.MapClaims{
		"role": "admin",
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler(next).ServeHTTP(rec, req)
	assert.True(t, nextCalled)
}

func TestRequireRole_BlocksWrongRole(t *testing.T) {
	handler := RequireRole("admin")
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	ctx := context.WithValue(context.Background(), claimsKey, jwt.MapClaims{
		"role": "viewer",
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler(next).ServeHTTP(rec, req)
	assert.False(t, nextCalled)
	assert.Equal(t, rec.Code, http.StatusForbidden)
}

func TestRequireRole_MultipleRoles(t *testing.T) {
	t.Run("viewer allowed", func(t *testing.T) {
		handler := RequireRole("admin", "viewer")
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		ctx := context.WithValue(context.Background(), claimsKey, jwt.MapClaims{
			"role": "viewer",
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		handler(next).ServeHTTP(rec, req)
		assert.True(t, nextCalled)
	})

	t.Run("no match", func(t *testing.T) {
		handler := RequireRole("admin", "viewer")
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		ctx := context.WithValue(context.Background(), claimsKey, jwt.MapClaims{
			"role": "superadmin",
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		handler(next).ServeHTTP(rec, req)
		assert.False(t, nextCalled)
	})
}

func TestRequireRole_NilClaims(t *testing.T) {
	handler := RequireRole("admin")
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil) // no claims in context
	rec := httptest.NewRecorder()

	handler(next).ServeHTTP(rec, req)
	assert.False(t, nextCalled)
	assert.Equal(t, rec.Code, http.StatusForbidden)
}

// Test that SetSecret panics on empty secret
func TestSetSecret_PanicsOnEmpty(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for empty secret")
		}
	}()
	// Use a different secret to not affect other tests
	SetSecret("")
	_ = strings.TrimSpace("just to avoid unused")
}

func TestIssueToken_PanicsWithoutSecret(t *testing.T) {
	// Save original
	orig := secret
	secret = ""
	defer func() {
		secret = orig
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()
	IssueToken("test", "admin", "usr_000")
}

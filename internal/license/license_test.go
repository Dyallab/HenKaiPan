package license

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"aspm/internal/assert"
)

// createSignedKey generates a valid signed license key for testing.
// Format: base64(payload) + "." + base64(signature)
// The '.' separator is unambiguous because base64 output never contains '.'.
func createSignedKey(t *testing.T, claims Claims) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	svc := &Service{signingSecret: builtinSigningSecret()}
	sig := svc.computeSignature(payload)

	return base64.StdEncoding.EncodeToString(payload) + "." + base64.StdEncoding.EncodeToString(sig)
}

func TestNew_EmptyKey(t *testing.T) {
	svc := New("")
	assert.False(t, svc.IsActive())
	assert.False(t, svc.HasFeature("scheduling"))

	st := svc.Status()
	assert.Equal(t, st.Status, "inactive")
	assert.Equal(t, st.Message, "No license key configured — running in free mode.")
}

func TestNew_InvalidKey(t *testing.T) {
	svc := New("this-is-not-a-valid-base64-key")
	assert.False(t, svc.IsActive())

	st := svc.Status()
	assert.Equal(t, st.Status, "invalid")
	assert.Equal(t, st.Message, "License key is invalid.")
}

func TestNew_ValidKey(t *testing.T) {
	claims := Claims{
		Email:    "customer@example.com",
		Expiry:   time.Now().Add(365 * 24 * time.Hour).Unix(),
		Features: []string{"scheduling", "teams", "policies"},
	}
	key := createSignedKey(t, claims)

	svc := New(key)
	assert.True(t, svc.IsActive())

	st := svc.Status()
	assert.Equal(t, st.Status, "active")
	assert.Equal(t, st.Message, "License is valid and active.")
	assert.Equal(t, st.Email, "customer@example.com")
	assert.NotNil(t, st.Expiry)
	assert.Equal(t, len(st.Features), 3)
}

func TestNew_ExpiredKey(t *testing.T) {
	claims := Claims{
		Email:    "expired@example.com",
		Expiry:   time.Now().Add(-24 * time.Hour).Unix(), // yesterday
		Features: []string{"scheduling"},
	}
	key := createSignedKey(t, claims)

	svc := New(key)
	assert.False(t, svc.IsActive())

	st := svc.Status()
	assert.Equal(t, st.Status, "expired")
	assert.Equal(t, st.Message, "License has expired.")
	assert.Equal(t, st.Email, "expired@example.com")
}

func TestHasFeature_Granted(t *testing.T) {
	claims := Claims{
		Email:    "test@example.com",
		Expiry:   time.Now().Add(30 * 24 * time.Hour).Unix(),
		Features: []string{"scheduling", "teams"},
	}
	key := createSignedKey(t, claims)
	svc := New(key)

	assert.True(t, svc.HasFeature("scheduling"))
	assert.True(t, svc.HasFeature("teams"))
}

func TestHasFeature_NotGranted(t *testing.T) {
	claims := Claims{
		Email:    "test@example.com",
		Expiry:   time.Now().Add(30 * 24 * time.Hour).Unix(),
		Features: []string{"scheduling", "teams"},
	}
	key := createSignedKey(t, claims)
	svc := New(key)

	assert.False(t, svc.HasFeature("compliance"))
	assert.False(t, svc.HasFeature("audit-log"))
	assert.False(t, svc.HasFeature("nonexistent"))
}

func TestHasFeature_NoLicense(t *testing.T) {
	svc := New("")
	assert.False(t, svc.HasFeature("scheduling"))
	assert.False(t, svc.HasFeature("teams"))
	assert.False(t, svc.HasFeature("compliance"))
}

func TestStatus_Messages(t *testing.T) {
	tests := []struct {
		name     string
		license  string
		wantSt   string
		wantMsg  string
	}{
		{"inactive", "", "inactive", "No license key configured"},
		{"invalid", "bad-key-!!!", "invalid", "License key is invalid"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := New(tc.license)
			st := svc.Status()
			assert.Equal(t, st.Status, tc.wantSt)
			assert.True(t, contains(st.Message, tc.wantMsg))
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestParse_InvalidBase64(t *testing.T) {
	svc := &Service{signingSecret: builtinSigningSecret()}
	_, err := svc.parse("!!!invalid-base64!!!")
	assert.True(t, err != nil)
}

func TestParse_NoSeparator(t *testing.T) {
	// valid base64 but no '.' separator
	svc := &Service{signingSecret: builtinSigningSecret()}
	encoded := base64.StdEncoding.EncodeToString([]byte(`{"email":"test"}`))
	_, err := svc.parse(encoded)
	assert.True(t, err != nil)
}

func TestFeatureConstants(t *testing.T) {
	// Verify all feature constants are non-empty
	assert.NotEqual(t, FeatureScheduling, "")
	assert.NotEqual(t, FeaturePolicies, "")
	assert.NotEqual(t, FeatureCompliance, "")
	assert.NotEqual(t, FeatureIntegrations, "")
	assert.NotEqual(t, FeatureAIRemediation, "")
	assert.NotEqual(t, FeatureReports, "")
	assert.NotEqual(t, FeatureAuditLog, "")
	assert.NotEqual(t, FeatureRiskAcceptance, "")
	assert.NotEqual(t, FeatureTeams, "")
	assert.NotEqual(t, FeatureComments, "")
	assert.NotEqual(t, FeatureEmailNotify, "")
}

package license

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"time"
)

// Claims represents the payload inside a signed license key.
type Claims struct {
	Email    string   `json:"email"`
	Expiry   int64    `json:"expiry"`
	Features []string `json:"features"`
}

// Status describes the current state of the license.
type Status struct {
	Valid    bool       `json:"valid"`
	Status   string     `json:"status"` // "active", "inactive", "expired", "invalid"
	Email    string     `json:"email,omitempty"`
	Expiry   *time.Time `json:"expiry,omitempty"`
	Features []string   `json:"features,omitempty"`
	Message  string     `json:"message,omitempty"`
}

// Service parses and validates license keys, and provides feature checks.
type Service struct {
	signingSecret string
	claims        *Claims
	valid         bool
	status        string // parsed status: "active", "inactive", "expired", "invalid"
}

// New creates a Service from the given license key.
// The signing secret is embedded in the binary — no env var required.
// When licenseKey is empty the service operates in free mode (no features).
func New(licenseKey string) *Service {
	svc := &Service{signingSecret: builtinSigningSecret()}

	if licenseKey == "" {
		svc.status = "inactive"
		return svc
	}

	claims, err := svc.parse(licenseKey)
	if err != nil {
		slog.Warn("failed to parse license key", "err", err)
		svc.status = "invalid"
		svc.valid = false
		return svc
	}

	expiry := time.Unix(claims.Expiry, 0)
	if time.Now().After(expiry) {
		slog.Warn("license key expired", "email", claims.Email, "expired_at", expiry)
		svc.status = "expired"
		svc.claims = claims
		return svc
	}

	svc.claims = claims
	svc.valid = true
	svc.status = "active"
	slog.Info("license key loaded",
		"email", claims.Email,
		"expiry", expiry.Format("2006-01-02"),
		"features", claims.Features,
	)
	return svc
}

// IsActive returns true when a valid, non-expired license key is configured.
func (s *Service) IsActive() bool {
	return s.valid
}

// HasFeature returns true when the license grants the named feature.
// Without a valid license key all feature checks return false.
func (s *Service) HasFeature(feature string) bool {
	return s.valid && s.claims != nil && slices.Contains(s.claims.Features, feature)
}

// Status returns a snapshot of the current license state.
func (s *Service) Status() Status {
	st := Status{
		Valid:  s.valid,
		Status: s.status,
	}
	if s.claims != nil {
		st.Email = s.claims.Email
		st.Features = s.claims.Features
		if s.claims.Expiry > 0 {
			t := time.Unix(s.claims.Expiry, 0)
			st.Expiry = &t
		}
	}
	switch s.status {
	case "inactive":
		st.Message = "No license key configured — running in free mode."
	case "invalid":
		st.Message = "License key is invalid."
	case "expired":
		st.Message = "License has expired."
	case "active":
		st.Message = "License is valid and active."
	}
	return st
}

func (s *Service) parse(key string) (*Claims, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	lastSep := -1
	for i := len(decoded) - 1; i >= 0; i-- {
		if decoded[i] == '.' {
			lastSep = i
			break
		}
	}
	if lastSep == -1 {
		return nil, fmt.Errorf("invalid format: no separator")
	}

	payload := decoded[:lastSep]
	signature := decoded[lastSep+1:]

	expectedSig := s.computeSignature(payload)
	if !hmac.Equal(signature, expectedSig) {
		return nil, fmt.Errorf("invalid signature")
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return &claims, nil
}

func (s *Service) computeSignature(payload []byte) []byte {
	h := hmac.New(sha256.New, []byte(s.signingSecret))
	h.Write(payload)
	return h.Sum(nil)
}

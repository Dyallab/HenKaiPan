package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type LicenseClaims struct {
	Email    string   `json:"email"`
	Expiry   int64    `json:"expiry"`
	Features []string `json:"features"`
}

type LicenseResponse struct {
	Valid       bool       `json:"valid"`
	Status      string     `json:"status"`
	Email       string     `json:"email,omitempty"`
	Expiry      *time.Time `json:"expiry,omitempty"`
	Features    []string   `json:"features,omitempty"`
	Message     string     `json:"message,omitempty"`
}

func (h *Handler) GetLicense(w http.ResponseWriter, r *http.Request) {
	licenseKey := h.licenseKey

	if licenseKey == "" {
		writeJSON(w, http.StatusOK, LicenseResponse{
			Valid:   false,
			Status:  "inactive",
			Message: "No license key configured. Set LICENSE_KEY environment variable.",
		})
		return
	}

	claims, err := parseLicense(licenseKey)
	if err != nil {
		writeJSON(w, http.StatusOK, LicenseResponse{
			Valid:   false,
			Status:  "invalid",
			Message: "Invalid license key format: " + err.Error(),
		})
		return
	}

	expiry := time.Unix(claims.Expiry, 0)
	if time.Now().After(expiry) {
		writeJSON(w, http.StatusOK, LicenseResponse{
			Valid:   false,
			Status:  "expired",
			Email:   claims.Email,
			Expiry:  &expiry,
			Message: "License expired on " + expiry.Format("2006-01-02"),
		})
		return
	}

	writeJSON(w, http.StatusOK, LicenseResponse{
		Valid:    true,
		Status:   "active",
		Email:    claims.Email,
		Expiry:   &expiry,
		Features: claims.Features,
	})
}

func parseLicense(key string) (*LicenseClaims, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	lastSep := -1
	for i := len(decoded) - 1; i >= 0; i-- {
		if decoded[i] == '.' {
			lastSep = i
			break
		}
	}

	if lastSep == -1 {
		return nil, fmt.Errorf("invalid license format")
	}

	payload := decoded[:lastSep]
	signature := decoded[lastSep+1:]

	expectedSig := computeSignature(payload)
	if !hmac.Equal(signature, expectedSig) {
		return nil, fmt.Errorf("invalid signature")
	}

	var claims LicenseClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

func computeSignature(payload []byte) []byte {
	h := hmac.New(sha256.New, []byte("aspm-license-secret"))
	h.Write(payload)
	return h.Sum(nil)
}

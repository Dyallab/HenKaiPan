package webhook

import (
	"net/http/httptest"
	"testing"
	"time"

	"aspm/internal/assert"
)

func TestSignPayload_Deterministic(t *testing.T) {
	secret := []byte("webhook-secret-123")
	payload := []byte(`{"event":"scan.completed","id":"scan_001"}`)
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	sig1 := SignPayload(payload, secret, ts)
	sig2 := SignPayload(payload, secret, ts)
	assert.Equal(t, sig1, sig2)
	assert.True(t, sig1 != "")
}

func TestSignPayload_DifferentInputs(t *testing.T) {
	secret := []byte("test-secret")
	ts := time.Now()

	sig1 := SignPayload([]byte("payload-a"), secret, ts)
	sig2 := SignPayload([]byte("payload-b"), secret, ts)
	assert.NotEqual(t, sig1, sig2)
}

func TestVerifySignature_HappyPath(t *testing.T) {
	secret := []byte("webhook-secret")
	body := []byte(`{"event":"scan.completed"}`)
	ts := time.Now()

	sig := SignPayload(body, secret, ts)

	req := httptest.NewRequest("POST", "/webhook", nil)
	req.Header.Set(SignatureHeader, sig)
	req.Header.Set(TimestampHeader, ts.Format(time.RFC3339))

	err := VerifySignature(req, body, secret)
	assert.NoError(t, err)
}

func TestVerifySignature_MissingSignature(t *testing.T) {
	req := httptest.NewRequest("POST", "/webhook", nil)
	req.Header.Set(TimestampHeader, time.Now().Format(time.RFC3339))

	err := VerifySignature(req, []byte("body"), []byte("secret"))
	assert.True(t, err != nil)
}

func TestVerifySignature_MissingTimestamp(t *testing.T) {
	req := httptest.NewRequest("POST", "/webhook", nil)
	req.Header.Set(SignatureHeader, "some-signature")

	err := VerifySignature(req, []byte("body"), []byte("secret"))
	assert.True(t, err != nil)
}

func TestVerifySignature_Expired(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte("hello")
	oldTS := time.Now().Add(-10 * time.Minute) // older than MaxAge (5 min)

	sig := SignPayload(body, secret, oldTS)

	req := httptest.NewRequest("POST", "/webhook", nil)
	req.Header.Set(SignatureHeader, sig)
	req.Header.Set(TimestampHeader, oldTS.Format(time.RFC3339))

	err := VerifySignature(req, body, secret)
	assert.ErrorIs(t, err, ErrExpiredTimestamp)
}

func TestVerifySignature_WrongSignature(t *testing.T) {
	body := []byte("hello")
	ts := time.Now()
	secret := []byte("real-secret")

	sig := SignPayload(body, secret, ts)

	req := httptest.NewRequest("POST", "/webhook", nil)
	req.Header.Set(SignatureHeader, sig)
	req.Header.Set(TimestampHeader, ts.Format(time.RFC3339))

	// Verify with different secret
	err := VerifySignature(req, body, []byte("wrong-secret"))
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

func TestVerifySignature_InvalidTimestampFormat(t *testing.T) {
	req := httptest.NewRequest("POST", "/webhook", nil)
	req.Header.Set(SignatureHeader, "sig")
	req.Header.Set(TimestampHeader, "not-a-timestamp")

	err := VerifySignature(req, []byte("body"), []byte("secret"))
	assert.True(t, err != nil)
}

func TestIsWithinTimeWindow_Fresh(t *testing.T) {
	err := IsWithinTimeWindow(time.Now().Format(time.RFC3339), MaxAge)
	assert.NoError(t, err)
}

func TestIsWithinTimeWindow_Expired(t *testing.T) {
	past := time.Now().Add(-10 * time.Minute)
	err := IsWithinTimeWindow(past.Format(time.RFC3339), MaxAge)
	assert.ErrorIs(t, err, ErrExpiredTimestamp)
}

func TestIsWithinTimeWindow_Empty(t *testing.T) {
	err := IsWithinTimeWindow("", MaxAge)
	assert.True(t, err != nil)
}

func TestIsWithinTimeWindow_InvalidFormat(t *testing.T) {
	err := IsWithinTimeWindow("bogus", MaxAge)
	assert.True(t, err != nil)
}

func TestGetSignatureHeaders_ReturnsBothHeaders(t *testing.T) {
	payload := []byte("test")
	secret := []byte("secret")

	headers, ts := GetSignatureHeaders(payload, secret)

	assert.NotNil(t, headers)
	assert.True(t, headers[SignatureHeader] != "")
	assert.True(t, headers[TimestampHeader] != "")
	assert.Equal(t, headers[TimestampHeader], ts.Format(time.RFC3339))
}

func TestVerifySignatureWithBody_Equivalent(t *testing.T) {
	secret := []byte("secret")
	body := []byte("test-body")
	ts := time.Now()
	sig := SignPayload(body, secret, ts)

	req := httptest.NewRequest("POST", "/webhook", nil)
	req.Header.Set(SignatureHeader, sig)
	req.Header.Set(TimestampHeader, ts.Format(time.RFC3339))

	err := VerifySignatureWithBody(req, body, secret)
	assert.NoError(t, err)
}

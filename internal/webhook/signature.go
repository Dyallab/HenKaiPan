package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

const (
	// SignatureHeader is the header name for webhook signature
	SignatureHeader = "X-Webhook-Signature"
	// TimestampHeader is the header name for webhook timestamp
	TimestampHeader = "X-Webhook-Timestamp"
	// MaxAge is the maximum age of a webhook request (5 minutes)
	MaxAge = 5 * time.Minute
)

// ErrInvalidSignature is returned when webhook signature validation fails
var ErrInvalidSignature = errors.New("invalid webhook signature")

// ErrExpiredTimestamp is returned when webhook timestamp is too old
var ErrExpiredTimestamp = errors.New("webhook timestamp expired")

// SignPayload creates an HMAC-SHA256 signature for outbound webhooks
func SignPayload(payload []byte, secret []byte, timestamp time.Time) string {
	// Create message: timestamp + "." + payload
	message := []byte(timestamp.Format(time.RFC3339) + "." + string(payload))

	// Create HMAC-SHA256
	h := hmac.New(sha256.New, secret)
	h.Write(message)

	// Return base64-encoded signature
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// VerifySignature validates the HMAC signature of an inbound webhook
func VerifySignature(r *http.Request, body []byte, secret []byte) error {
	signature := r.Header.Get(SignatureHeader)
	timestampStr := r.Header.Get(TimestampHeader)

	if signature == "" {
		return errors.New("missing signature header")
	}

	if timestampStr == "" {
		return errors.New("missing timestamp header")
	}

	// Parse timestamp
	timestamp, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return errors.New("invalid timestamp format")
	}

	// Check if timestamp is within acceptable window
	if time.Since(timestamp) > MaxAge {
		return ErrExpiredTimestamp
	}

	// Create expected signature
	expectedSig := SignPayload(body, secret, timestamp)

	// Constant-time comparison to prevent timing attacks
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return ErrInvalidSignature
	}

	return nil
}

// VerifySignatureWithBody is a convenience function that reads body and verifies signature
// Use this when you haven't read the body yet
func VerifySignatureWithBody(r *http.Request, body []byte, secret []byte) error {
	return VerifySignature(r, body, secret)
}

// IsWithinTimeWindow checks if a request timestamp is recent enough
func IsWithinTimeWindow(timestampHeader string, maxAge time.Duration) error {
	if timestampHeader == "" {
		return errors.New("missing timestamp")
	}

	timestamp, err := time.Parse(time.RFC3339, timestampHeader)
	if err != nil {
		return errors.New("invalid timestamp format")
	}

	if time.Since(timestamp) > maxAge {
		return ErrExpiredTimestamp
	}

	return nil
}

// GetSignatureHeaders returns the signature and timestamp headers for outbound webhooks
func GetSignatureHeaders(payload []byte, secret []byte) (map[string]string, time.Time) {
	timestamp := time.Now()
	signature := SignPayload(payload, secret, timestamp)

	headers := map[string]string{
		SignatureHeader: signature,
		TimestampHeader: timestamp.Format(time.RFC3339),
	}

	return headers, timestamp
}

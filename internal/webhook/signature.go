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



package httperrors

import (
	"errors"
	"os"
	"strings"
)

// Error codes for standardized error responses
const (
	ErrBadRequest          = "bad_request"
	ErrUnauthorized        = "unauthorized"
	ErrForbidden           = "forbidden"
	ErrNotFound            = "not_found"
	ErrConflict            = "conflict"
	ErrInternal            = "internal_error"
	ErrServiceUnavailable  = "service_unavailable"
	ErrRateLimited         = "rate_limited"
	ErrValidation          = "validation_error"
	ErrLicenseRequired     = "license_required"
	ErrFeatureNotAvailable = "feature_not_available"
)

// HTTPError represents a standardized HTTP error response
type HTTPError struct {
	Code     string            `json:"code"`               // Machine-readable error code
	Message  string            `json:"message"`            // Human-readable message
	Details  string            `json:"details,omitempty"`  // Optional debug information
	Metadata map[string]string `json:"metadata,omitempty"` // Additional context
}

// Error implements the error interface
func (e *HTTPError) Error() string {
	if e.Details != "" {
		return e.Message + ": " + e.Details
	}
	return e.Message
}

// New creates a new HTTPError with the given code and message
func New(code, message string, details ...string) *HTTPError {
	err := &HTTPError{
		Code:    code,
		Message: message,
	}
	if len(details) > 0 {
		err.Details = details[0]
	}
	return err
}

// Wrap wraps an existing error with additional context
func Wrap(err error, code, message string) *HTTPError {
	if err == nil {
		return nil
	}
	return &HTTPError{
		Code:    code,
		Message: message,
		Details: err.Error(),
	}
}

// WithMetadata adds metadata to the error
func (e *HTTPError) WithMetadata(key, value string) *HTTPError {
	if e.Metadata == nil {
		e.Metadata = make(map[string]string)
	}
	e.Metadata[key] = value
	return e
}

// IsNotFound checks if an error is a not found error
func IsNotFound(err error) bool {
	var httpErr *HTTPError
	return errors.As(err, &httpErr) && httpErr.Code == ErrNotFound
}

// IsUnauthorized checks if an error is an unauthorized error
func IsUnauthorized(err error) bool {
	var httpErr *HTTPError
	return errors.As(err, &httpErr) && httpErr.Code == ErrUnauthorized
}

// IsBadRequest checks if an error is a bad request error
func IsBadRequest(err error) bool {
	var httpErr *HTTPError
	return errors.As(err, &httpErr) && httpErr.Code == ErrBadRequest
}

// isProduction returns true if the app is running in production mode
func isProduction() bool {
	return os.Getenv("PRODUCTION") == "true"
}

// MapError maps common errors to HTTPError with appropriate status codes
// In production mode, details are sanitized to prevent information leakage
func MapError(err error, defaultMessage string) *HTTPError {
	if err == nil {
		return nil
	}

	// If already an HTTPError, return it (but sanitize if needed)
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		if isProduction() {
			// Sanitize HTTPError in production
			httpErr.Details = ""
		}
		return httpErr
	}

	// Check for specific error types
	errStr := strings.ToLower(err.Error())

	// Determine error details to return
	var details string
	if !isProduction() {
		details = err.Error()
	}

	switch {
	case strings.Contains(errStr, "not found"):
		return New(ErrNotFound, "Resource not found", details)
	case strings.Contains(errStr, "unauthorized"), strings.Contains(errStr, "invalid credentials"):
		return New(ErrUnauthorized, "Invalid credentials", details)
	case strings.Contains(errStr, "conflict"), strings.Contains(errStr, "duplicate"):
		return New(ErrConflict, "Resource already exists", details)
	case strings.Contains(errStr, "validation"):
		return New(ErrValidation, "Validation failed", details)
	default:
		return New(ErrInternal, defaultMessage, details)
	}
}

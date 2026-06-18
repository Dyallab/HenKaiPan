package httperrors


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




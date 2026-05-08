package httperrors

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestMapErrorProduction(t *testing.T) {
	os.Setenv("PRODUCTION", "true")
	defer os.Unsetenv("PRODUCTION")

	err := errors.New("pq: relation \"users\" does not exist")
	mapped := MapError(err, "An error occurred")

	if mapped.Code != ErrInternal {
		t.Errorf("expected code %s, got %s", ErrInternal, mapped.Code)
	}

	if strings.Contains(mapped.Details, "pq:") {
		t.Error("production error exposed database error details")
	}

	if strings.Contains(mapped.Details, "users") {
		t.Error("production error exposed table name")
	}

	if strings.Contains(mapped.Details, "pgx") {
		t.Error("production error exposed pgx driver details")
	}

	if mapped.Details != "" {
		t.Errorf("expected empty details in production, got: %s", mapped.Details)
	}
}

func TestMapErrorDevelopment(t *testing.T) {
	os.Setenv("PRODUCTION", "false")
	defer os.Unsetenv("PRODUCTION")

	err := errors.New("pq: relation \"users\" does not exist")
	mapped := MapError(err, "An error occurred")

	if mapped.Code != ErrInternal {
		t.Errorf("expected code %s, got %s", ErrInternal, mapped.Code)
	}

	if !strings.Contains(mapped.Details, "pq:") {
		t.Error("development error should contain full details")
	}

	if mapped.Details != err.Error() {
		t.Errorf("development error details should match original error, got: %s", mapped.Details)
	}
}

func TestMapErrorNotFound(t *testing.T) {
	os.Setenv("PRODUCTION", "true")
	defer os.Unsetenv("PRODUCTION")

	err := errors.New("not found")
	mapped := MapError(err, "Resource not found")

	if mapped.Code != ErrNotFound {
		t.Errorf("expected code %s, got %s", ErrNotFound, mapped.Code)
	}

	if mapped.Details != "" {
		t.Error("production error should have empty details")
	}
}

func TestMapErrorUnauthorized(t *testing.T) {
	os.Setenv("PRODUCTION", "true")
	defer os.Unsetenv("PRODUCTION")

	err := errors.New("invalid credentials provided")
	mapped := MapError(err, "Invalid credentials")

	if mapped.Code != ErrUnauthorized {
		t.Errorf("expected code %s, got %s", ErrUnauthorized, mapped.Code)
	}

	if mapped.Details != "" {
		t.Error("production error should have empty details")
	}
}

func TestMapErrorAlreadyHTTPError(t *testing.T) {
	os.Setenv("PRODUCTION", "true")
	defer os.Unsetenv("PRODUCTION")

	httpErr := New(ErrConflict, "Resource already exists", "duplicate key constraint")
	mapped := MapError(httpErr, "Default message")

	if mapped.Code != ErrConflict {
		t.Errorf("expected code %s, got %s", ErrConflict, mapped.Code)
	}

	if mapped.Details != "" {
		t.Error("production should sanitize HTTPError details")
	}
}

func TestMapErrorNil(t *testing.T) {
	mapped := MapError(nil, "Default message")
	if mapped != nil {
		t.Error("MapError(nil) should return nil")
	}
}

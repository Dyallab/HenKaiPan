package httperrors

import (
	"errors"
	"os"
	"strings"
	"testing"

	"aspm/internal/assert"
)

func TestMapErrorProduction(t *testing.T) {
	os.Setenv("PRODUCTION", "true")
	defer os.Unsetenv("PRODUCTION")

	err := errors.New("pq: relation \"users\" does not exist")
	mapped := MapError(err, "An error occurred")

	assert.Equal(t, mapped.Code, ErrInternal)
	assert.False(t, strings.Contains(mapped.Details, "pq:"))
	assert.False(t, strings.Contains(mapped.Details, "users"))
	assert.False(t, strings.Contains(mapped.Details, "pgx"))
	assert.Equal(t, mapped.Details, "")
}

func TestMapErrorDevelopment(t *testing.T) {
	os.Setenv("PRODUCTION", "false")
	defer os.Unsetenv("PRODUCTION")

	err := errors.New("pq: relation \"users\" does not exist")
	mapped := MapError(err, "An error occurred")

	assert.Equal(t, mapped.Code, ErrInternal)
	assert.True(t, strings.Contains(mapped.Details, "pq:"))
	assert.Equal(t, mapped.Details, err.Error())
}

func TestMapErrorNotFound(t *testing.T) {
	os.Setenv("PRODUCTION", "true")
	defer os.Unsetenv("PRODUCTION")

	err := errors.New("not found")
	mapped := MapError(err, "Resource not found")

	assert.Equal(t, mapped.Code, ErrNotFound)
	assert.Equal(t, mapped.Details, "")
}

func TestMapErrorUnauthorized(t *testing.T) {
	os.Setenv("PRODUCTION", "true")
	defer os.Unsetenv("PRODUCTION")

	err := errors.New("invalid credentials provided")
	mapped := MapError(err, "Invalid credentials")

	assert.Equal(t, mapped.Code, ErrUnauthorized)
	assert.Equal(t, mapped.Details, "")
}

func TestMapErrorAlreadyHTTPError(t *testing.T) {
	os.Setenv("PRODUCTION", "true")
	defer os.Unsetenv("PRODUCTION")

	httpErr := New(ErrConflict, "Resource already exists", "duplicate key constraint")
	mapped := MapError(httpErr, "Default message")

	assert.Equal(t, mapped.Code, ErrConflict)
	assert.Equal(t, mapped.Details, "")
}

func TestMapErrorNil(t *testing.T) {
	mapped := MapError(nil, "Default message")
	assert.Nil(t, mapped)
}

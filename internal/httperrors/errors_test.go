package httperrors

import (
	"testing"

	"aspm/internal/assert"
)

func TestNew_HTTPError(t *testing.T) {
	t.Run("with details", func(t *testing.T) {
		err := New(ErrNotFound, "not found", "user 42 missing")
		assert.Equal(t, err.Code, ErrNotFound)
		assert.Equal(t, err.Details, "user 42 missing")
	})

	t.Run("without details", func(t *testing.T) {
		err := New(ErrBadRequest, "bad request")
		assert.Equal(t, err.Code, ErrBadRequest)
		assert.Equal(t, err.Details, "")
	})
}

func TestWrap_HTTPError(t *testing.T) {
	original := New(ErrInternal, "internal error")
	wrapped := Wrap(original, ErrBadRequest, "wrapped")
	assert.Equal(t, wrapped.Code, ErrBadRequest)
	assert.Equal(t, wrapped.Details, "internal error")
}

func TestWrap_Nil(t *testing.T) {
	wrapped := Wrap(nil, ErrBadRequest, "should be nil")
	assert.Nil(t, wrapped)
}

func TestWithMetadata(t *testing.T) {
	err := New(ErrNotFound, "not found")
	err.WithMetadata("key", "value")
	assert.Equal(t, err.Metadata["key"], "value")
}

func TestHTTPError_Error(t *testing.T) {
	t.Run("with details", func(t *testing.T) {
		err := New(ErrInternal, "internal error", "db timeout")
		assert.Equal(t, err.Error(), "internal error: db timeout")
	})

	t.Run("without details", func(t *testing.T) {
		err := New(ErrBadRequest, "bad request")
		assert.Equal(t, err.Error(), "bad request")
	})
}

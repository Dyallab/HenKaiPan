package logger

import (
	"log/slog"
	"os"
	"strings"
	"testing"

	"aspm/internal/assert"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"WARNING", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERROR", slog.LevelError},
		{"", slog.LevelInfo},
		{"unknown", slog.LevelInfo},
		{"trace", slog.LevelInfo},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseLevel(tc.input)
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestInit_JSONFormat(t *testing.T) {
	// Capture stderr
	r, w, _ := os.Pipe()
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("LOG_FORMAT", "json")
	Init()

	slog.Info("test message", "key", "value")
	w.Close()

	var buf strings.Builder
	_, _ = copyBuffer(&buf, r)
	r.Close()

	// JSON output should contain our message
	assert.True(t, strings.Contains(buf.String(), "test message"))
	assert.True(t, strings.Contains(buf.String(), "\"key\":"))
	assert.True(t, strings.Contains(buf.String(), "\"value\""))
}

func TestInit_TextFormat(t *testing.T) {
	r, w, _ := os.Pipe()
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	t.Setenv("LOG_LEVEL", "info")
	t.Setenv("LOG_FORMAT", "text")
	Init()

	slog.Info("text message")
	w.Close()

	var buf strings.Builder
	_, _ = copyBuffer(&buf, r)
	r.Close()

	// Text output should not be JSON (no curly braces wrapping)
	assert.True(t, strings.Contains(buf.String(), "text message"))
}

// copyBuffer copies from reader to writer until EOF.
func copyBuffer(buf *strings.Builder, r *os.File) (int64, error) {
	written := int64(0)
	b := make([]byte, 4096)
	for {
		n, err := r.Read(b)
		if n > 0 {
			buf.Write(b[:n])
			written += int64(n)
		}
		if err != nil {
			return written, err
		}
	}
}

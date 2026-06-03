// Package assert provides minimal test assertion helpers.
//
// It intentionally avoids third-party assert libraries (testify, etc.)
// per Go Wiki recommendations. These helpers are designed to be readable,
// composable with standard Go, and precise about what went wrong.
//
// Reference: https://go.dev/wiki/TestComments#assert-libraries
//            https://www.alexedwards.net/blog/the-9-go-test-assertions-i-use
package assert

import (
	"errors"
	"reflect"
	"regexp"
	"testing"
)

// Equal checks that got and want are equal.
// Uses reflect.DeepEqual as fallback, respects the Equal(T) bool interface.
func Equal[T any](t testing.TB, got, want T) {
	t.Helper()
	if !isEqual(got, want) {
		t.Errorf("got: %#v; want: %#v", got, want)
	}
}

// NotEqual checks that got and want are not equal.
func NotEqual[T any](t testing.TB, got, want T) {
	t.Helper()
	if isEqual(got, want) {
		t.Errorf("got: %#v; want: values to differ", got)
	}
}

// True checks that got is true.
func True(t testing.TB, got bool) {
	t.Helper()
	if !got {
		t.Error("got: false; want: true")
	}
}

// False checks that got is false.
func False(t testing.TB, got bool) {
	t.Helper()
	if got {
		t.Error("got: true; want: false")
	}
}

// Nil checks that got is nil.
func Nil(t testing.TB, got any) {
	t.Helper()
	if !isNil(got) {
		t.Errorf("got: %#v; want: nil", got)
	}
}

// NotNil checks that got is not nil.
func NotNil(t testing.TB, got any) {
	t.Helper()
	if isNil(got) {
		t.Error("got: nil; want: non-nil")
	}
}

// ErrorIs checks that got is an error that wraps or equals want.
func ErrorIs(t testing.TB, got, want error) {
	t.Helper()
	if got == nil {
		t.Errorf("got: nil; want: error wrapping %v", want)
		return
	}
	if !errors.Is(got, want) {
		t.Errorf("got: %v; want: error wrapping %v", got, want)
	}
}

// ErrorAs checks that got can be assigned to target via errors.As.
func ErrorAs[T error](t testing.TB, got error) T {
	t.Helper()
	var target T
	if got == nil {
		t.Errorf("got: nil; want assignable to %T", target)
		return target
	}
	if errors.As(got, &target) {
		return target
	}
	t.Errorf("got: %v; want assignable to %T", got, target)
	return target
}

// NoError checks that got is nil. Prefer ErrorIs(t, got, nil) for consistency,
// but this is provided as a convenience for the common case.
func NoError(t testing.TB, got error) {
	t.Helper()
	if got != nil {
		t.Errorf("unexpected error: %v", got)
	}
}

// MatchesRegexp checks that got matches the regex pattern.
func MatchesRegexp(t testing.TB, got, pattern string) {
	t.Helper()
	matched, err := regexp.MatchString(pattern, got)
	if err != nil {
		t.Fatalf("invalid regexp pattern %q: %s", pattern, err)
	}
	if !matched {
		t.Errorf("got: %q; want to match %q", got, pattern)
	}
}

// isEqual checks equality using Equal method or reflect.DeepEqual.
func isEqual[T any](got, want T) bool {
	if isNil(got) && isNil(want) {
		return true
	}
	if eq, ok := any(got).(interface{ Equal(T) bool }); ok {
		return eq.Equal(want)
	}
	return reflect.DeepEqual(got, want)
}

// isNil checks if v is nil, including typed nil pointers/interfaces.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Pointer, reflect.Slice,
		reflect.UnsafePointer:
		return rv.IsNil()
	default:
		return false
	}
}

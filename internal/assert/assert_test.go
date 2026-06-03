package assert

import (
	"io"
	"regexp"
	"testing"
)

// silentT wraps *testing.T and captures assertion failures silently
// without propagating them to the parent test.
type silentT struct {
	*testing.T
	failed bool
}

func (t *silentT) Error(args ...any)                { t.failed = true }
func (t *silentT) Errorf(format string, args ...any) { t.failed = true }
func (t *silentT) Fatal(args ...any)                { t.failed = true }
func (t *silentT) Fatalf(format string, args ...any) { t.failed = true }
func (t *silentT) Fail()                             { t.failed = true }
func (t *silentT) FailNow()                          { t.failed = true }

// assertFails verifies that fn causes an assertion failure.
func assertFails(t *testing.T, fn func(tt testing.TB)) {
	t.Helper()
	st := &silentT{T: t}
	fn(st)
	if !st.failed {
		t.Error("expected assertion to fail, but it passed")
	}
}

func TestEqual_Passes(t *testing.T) {
	Equal(t, 42, 42)
	Equal(t, "hello", "hello")
	Equal(t, 3.14, 3.14)
}

func TestEqual_Fails(t *testing.T) {
	assertFails(t, func(tt testing.TB) {
		Equal(tt, 42, 43)
	})
}

func TestEqual_NilValues(t *testing.T) {
	var s []int
	Equal[[]int](t, s, nil)
	var m map[string]int
	Equal[map[string]int](t, m, nil)
}

func TestEqual_WithEqualMethod(t *testing.T) {
	a := regexp.MustCompile(`^foo`)
	b := regexp.MustCompile(`^foo`)
	Equal(t, a, b)

	assertFails(t, func(tt testing.TB) {
		c := regexp.MustCompile(`^bar`)
		Equal(tt, a, c)
	})
}

func TestNotEqual_Passes(t *testing.T) {
	NotEqual(t, 42, 43)
	NotEqual(t, "hello", "world")
}

func TestNotEqual_Fails(t *testing.T) {
	assertFails(t, func(tt testing.TB) {
		NotEqual(tt, 42, 42)
	})
}

func TestTrue_Passes(t *testing.T) {
	True(t, 1 == 1)
	True(t, true)
}

func TestTrue_Fails(t *testing.T) {
	assertFails(t, func(tt testing.TB) {
		True(tt, false)
	})
}

func TestFalse_Passes(t *testing.T) {
	False(t, 1 == 2)
	False(t, false)
}

func TestFalse_Fails(t *testing.T) {
	assertFails(t, func(tt testing.TB) {
		False(tt, true)
	})
}

func TestNil_Passes(t *testing.T) {
	Nil(t, nil)
	var s []int
	Nil(t, s)
	var m map[string]int
	Nil(t, m)
	var p *int
	Nil(t, p)
}

func TestNil_Fails(t *testing.T) {
	assertFails(t, func(tt testing.TB) {
		Nil(tt, 42)
	})
}

func TestNotNil_Passes(t *testing.T) {
	NotNil(t, 42)
	NotNil(t, "hello")
	NotNil(t, struct{}{})
}

func TestNotNil_Fails(t *testing.T) {
	assertFails(t, func(tt testing.TB) {
		NotNil(tt, nil)
	})
	assertFails(t, func(tt testing.TB) {
		var s []int
		NotNil(tt, s)
	})
}

func TestErrorIs_Passes(t *testing.T) {
	ErrorIs(t, io.EOF, io.EOF)
}

func TestErrorIs_Wraps(t *testing.T) {
	wrapped := &wrapError{msg: "wrapped: EOF", inner: io.EOF}
	ErrorIs(t, wrapped, io.EOF)
}

type wrapError struct {
	msg   string
	inner error
}

func (e *wrapError) Error() string { return e.msg }
func (e *wrapError) Unwrap() error { return e.inner }

func TestErrorIs_Fails(t *testing.T) {
	assertFails(t, func(tt testing.TB) {
		ErrorIs(tt, io.EOF, io.ErrClosedPipe)
	})
}

func TestErrorIs_Nil(t *testing.T) {
	assertFails(t, func(tt testing.TB) {
		ErrorIs(tt, nil, io.EOF)
	})
}

type sentinelError struct{ msg string }

func (e *sentinelError) Error() string { return e.msg }

func TestErrorAs_Passes(t *testing.T) {
	err := &sentinelError{msg: "test"}
	got := ErrorAs[*sentinelError](t, err)
	if got == nil {
		t.Error("expected non-nil result from ErrorAs")
	}
	if got.msg != "test" {
		t.Errorf("got msg %q, want %q", got.msg, "test")
	}
}

func TestErrorAs_Nil(t *testing.T) {
	assertFails(t, func(tt testing.TB) {
		ErrorAs[*sentinelError](tt, nil)
	})
}

func TestErrorAs_Mismatch(t *testing.T) {
	assertFails(t, func(tt testing.TB) {
		ErrorAs[*sentinelError](tt, io.EOF)
	})
}

func TestNoError_Passes(t *testing.T) {
	NoError(t, nil)
}

func TestNoError_Fails(t *testing.T) {
	assertFails(t, func(tt testing.TB) {
		NoError(tt, io.EOF)
	})
}

func TestMatchesRegexp_Passes(t *testing.T) {
	MatchesRegexp(t, "hello world", `^hello`)
	MatchesRegexp(t, "abc123", `\d+`)
}

func TestMatchesRegexp_Fails(t *testing.T) {
	assertFails(t, func(tt testing.TB) {
		MatchesRegexp(tt, "hello world", `^\d+`)
	})
}

func TestMatchesRegexp_InvalidPattern(t *testing.T) {
	assertFails(t, func(tt testing.TB) {
		MatchesRegexp(tt, "hello", `[invalid`)
	})
}

func TestEqual_ByteSlices(t *testing.T) {
	Equal(t, []byte("hello"), []byte("hello"))

	assertFails(t, func(tt testing.TB) {
		Equal(tt, []byte("hello"), []byte("world"))
	})
}

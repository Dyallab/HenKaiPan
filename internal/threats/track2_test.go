package threats

import "testing"

func TestTrack2DefaultRuntimeStatus(t *testing.T) {
	if got := DefaultRuntimeStatus(); got != RuntimeStatusL0 {
		t.Fatalf("DefaultRuntimeStatus() = %q, want %q", got, RuntimeStatusL0)
	}
}

func TestTrack2PromoteForward(t *testing.T) {
	levels := []RuntimeStatus{
		RuntimeStatusL0,
		RuntimeStatusL1,
		RuntimeStatusL2,
		RuntimeStatusL3,
		RuntimeStatusL4,
	}
	for i := 0; i < len(levels)-1; i++ {
		got, err := PromoteRuntime(levels[i], levels[i+1])
		if err != nil {
			t.Fatalf("PromoteRuntime(%q -> %q) unexpected error: %v", levels[i], levels[i+1], err)
		}
		if got != levels[i+1] {
			t.Fatalf("PromoteRuntime(%q -> %q) = %q, want %q", levels[i], levels[i+1], got, levels[i+1])
		}
	}
}

func TestTrack2PromoteSameLevel(t *testing.T) {
	for _, lvl := range []RuntimeStatus{RuntimeStatusL0, RuntimeStatusL1, RuntimeStatusL2, RuntimeStatusL3, RuntimeStatusL4} {
		got, err := PromoteRuntime(lvl, lvl)
		if err != nil {
			t.Fatalf("PromoteRuntime(%q -> %q) unexpected error: %v", lvl, lvl, err)
		}
		if got != lvl {
			t.Fatalf("PromoteRuntime(%q -> %q) = %q, want %q", lvl, lvl, got, lvl)
		}
	}
}

func TestTrack2PromoteSkipForward(t *testing.T) {
	got, err := PromoteRuntime(RuntimeStatusL0, RuntimeStatusL4)
	if err != nil {
		t.Fatalf("PromoteRuntime(L0 -> L4) unexpected error: %v", err)
	}
	if got != RuntimeStatusL4 {
		t.Fatalf("PromoteRuntime(L0 -> L4) = %q, want %q", got, RuntimeStatusL4)
	}
}

func TestTrack2PromoteDowngradeErrors(t *testing.T) {
	if _, err := PromoteRuntime(RuntimeStatusL2, RuntimeStatusL1); err == nil {
		t.Fatal("PromoteRuntime(L2 -> L1) expected error, got nil")
	}
	if _, err := PromoteRuntime(RuntimeStatusL4, RuntimeStatusL0); err == nil {
		t.Fatal("PromoteRuntime(L4 -> L0) expected error, got nil")
	}
}

func TestTrack2PromoteInvalidLevelErrors(t *testing.T) {
	for _, tc := range [][2]RuntimeStatus{
		{"L9", RuntimeStatusL1},
		{RuntimeStatusL0, "L9"},
		{"", RuntimeStatusL0},
		{RuntimeStatusL0, ""},
	} {
		if _, err := PromoteRuntime(tc[0], tc[1]); err == nil {
			t.Fatalf("PromoteRuntime(%q -> %q) expected error, got nil", tc[0], tc[1])
		}
	}
}

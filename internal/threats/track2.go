package threats

import "fmt"

// F3-F5: Nuclei/SIEM stub — no pipeline; full Track2 assessment deferred.

// RuntimeStatus is the Track2 runtime assessment level (L0-L4).
type RuntimeStatus string

const (
	RuntimeStatusL0 RuntimeStatus = "L0"
	RuntimeStatusL1 RuntimeStatus = "L1"
	RuntimeStatusL2 RuntimeStatus = "L2"
	RuntimeStatusL3 RuntimeStatus = "L3"
	RuntimeStatusL4 RuntimeStatus = "L4"
)

// DefaultRuntimeStatus returns the default runtime status for unscanned
// findings: L0.
func DefaultRuntimeStatus() RuntimeStatus {
	return RuntimeStatusL0
}

func runtimeRank(s RuntimeStatus) (int, bool) {
	switch s {
	case RuntimeStatusL0:
		return 0, true
	case RuntimeStatusL1:
		return 1, true
	case RuntimeStatusL2:
		return 2, true
	case RuntimeStatusL3:
		return 3, true
	case RuntimeStatusL4:
		return 4, true
	default:
		return -1, false
	}
}

// PromoteRuntime moves a finding forward along L0→L1→L2→L3→L4.
// Same-level promotion is a no-op returning the level with nil error.
// Skip-forward (e.g. L0→L4) is allowed; any backward move (downgrade)
// returns an error. Unknown levels on either side return an error.
func PromoteRuntime(from, to RuntimeStatus) (RuntimeStatus, error) {
	fromRank, ok := runtimeRank(from)
	if !ok {
		return "", fmt.Errorf("invalid source runtime status %q", from)
	}
	toRank, ok := runtimeRank(to)
	if !ok {
		return "", fmt.Errorf("invalid target runtime status %q", to)
	}
	if toRank < fromRank {
		return "", fmt.Errorf("runtime status downgrade forbidden: %q -> %q", from, to)
	}
	return to, nil
}

package scanner

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Executor struct {
	binaries map[string]string
}

func NewExecutor() *Executor {
	return &Executor{
		binaries: map[string]string{
			"semgrep":     "semgrep",
			"gosec":       "gosec",
			"trivy":       "trivy",
			"trivy-image": "trivy",
			"grype":       "grype",
			"grype-image": "grype",
			"osv-scanner": "osv-scanner",
			"trufflehog":  "trufflehog",
			"gitleaks":    "gitleaks",
			"checkov":     "checkov",
			"tfsec":       "tfsec",
			"kics":        "kics",
			"nuclei":      "nuclei",
		},
	}
}

type ExecResult struct {
	Stdout []byte
	Log    string
	Err    error
}

func (e *Executor) RunScanner(ctx context.Context, sc Scanner, mountSrc string) ExecResult {
	binary, ok := e.binaries[sc.Name]
	if !ok {
		return ExecResult{
			Err: fmt.Errorf("no binary mapping for scanner: %s", sc.Name),
		}
	}

	args := e.buildArgs(sc, mountSrc)

	var cmd *exec.Cmd
	if sc.ExecVia != "" {
		shellPath, err := exec.LookPath(sc.ExecVia)
		if err != nil {
			return ExecResult{Err: fmt.Errorf("shell not found: %s", sc.ExecVia)}
		}
		cmd = exec.CommandContext(ctx, shellPath, args...)
	} else {
		binaryPath, err := exec.LookPath(binary)
		if err != nil {
			return ExecResult{
				Err: fmt.Errorf("scanner binary not found: %s (looked for '%s')", sc.Name, binary),
			}
		}
		cmd = exec.CommandContext(ctx, binaryPath, args...)
	}

	if sc.WorkDir != "" {
		cmd.Dir = mountSrc
	}

	if len(sc.Env) > 0 {
		cmd.Env = append(os.Environ(), envMapToSlice(sc.Env)...)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()
	elapsed := time.Since(start)

	cmdStr := binary + " " + strings.Join(args, " ")
	log := e.buildLog(cmdStr, stdout.Bytes(), stderr.Bytes(), runErr, elapsed)

	return ExecResult{
		Stdout: stdout.Bytes(),
		Log:    log,
		Err:    runErr,
	}
}

func (e *Executor) buildArgs(sc Scanner, targetDir string) []string {
	return sc.BuildArgs(targetDir)
}

func (e *Executor) buildLog(cmdStr string, stdout, stderr []byte, err error, elapsed time.Duration) string {
	var b strings.Builder

	// https://chanisha.medium.com/avoiding-for-string-concatenation-in-golang-8149822f3341
	b.WriteString("$ " + cmdStr + "\n")
	fmt.Fprintf(&b, "# elapsed: %s\n", elapsed.Round(time.Millisecond))

	if err != nil {
		fmt.Fprintf(&b, "# exit: %s\n", err)
	} else {
		b.WriteString("# exit: 0\n")
	}

	if len(stdout) > 0 {
		b.WriteString("\n─── STDOUT ────────────────────────────────\n")
		b.Write(truncate(stdout, maxLogBytes))
		if len(stdout) > maxLogBytes {
			fmt.Fprintf(&b, "\n[... truncated %d bytes ...]", len(stdout)-maxLogBytes)
		}
	}

	if len(stderr) > 0 {
		b.WriteString("\n─── STDERR ────────────────────────────────\n")
		b.Write(truncate(stderr, maxLogBytes))
		if len(stderr) > maxLogBytes {
			fmt.Fprintf(&b, "\n[... truncated %d bytes ...]", len(stderr)-maxLogBytes)
		}
	}

	return b.String()
}

func truncate(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	return b[:max]
}

func envMapToSlice(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}

const maxLogBytes = 100 * 1024

func CheckBinaryAvailability(scannerName string) (string, error) {
	binaries := map[string]string{
		"semgrep":     "semgrep",
		"gosec":       "gosec",
		"trivy":       "trivy",
		"trivy-image": "trivy",
		"grype":       "grype",
		"grype-image": "grype",
		"osv-scanner": "osv-scanner",
		"trufflehog":  "trufflehog",
		"gitleaks":    "gitleaks",
		"checkov":     "checkov",
		"tfsec":       "tfsec",
		"kics":        "kics",
		"nuclei":      "nuclei",
	}

	binary, ok := binaries[scannerName]
	if !ok {
		return "", fmt.Errorf("unknown scanner: %s", scannerName)
	}

	path, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("scanner %s not found in PATH", scannerName)
	}

	slog.Info("scanner binary found", "scanner", scannerName, "path", path)
	return path, nil
}

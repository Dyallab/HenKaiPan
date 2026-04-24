package tasks

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"aspm/internal/repository"
	"aspm/internal/scanner"

	"github.com/hibiken/asynq"
)

const maxLogBytes = 100 * 1024 // 100 KB per stream

type runResult struct {
	stdout []byte
	log    string
	err    error
}

// HandleScan is the single asynq handler for all scanners.
func HandleScan(scans repository.ScanRepository, findings repository.FindingRepository, policies repository.PolicyRepository, queue *asynq.Client) asynq.HandlerFunc {
	return func(ctx context.Context, t *asynq.Task) error {
		p, err := UnmarshalPayload(t.Payload())
		if err != nil {
			return err
		}

		log := slog.With("scan_id", p.ScanID, "scanner", p.Scanner, "target", p.Target)

		sc, ok := scanner.Get(p.Scanner)
		if !ok {
			return fmt.Errorf("unknown scanner: %s", p.Scanner)
		}

		if err := scans.MarkRunning(ctx, p.ScanID); err != nil {
			return fmt.Errorf("update status: %w", err)
		}

		log.Info("scan started")

		var result runResult

		switch sc.TargetType {
		case scanner.TargetGit:
			dir, cloneLog, err := cloneRepo(ctx, p.Target, p.ScanID)
			if err != nil {
				scans.MarkFailed(ctx, p.ScanID, err.Error(), cloneLog)
				log.Error("clone failed", "err", err)
				return err
			}
			defer os.RemoveAll(dir)
			result = runDocker(sc, dir)

		case scanner.TargetURL:
			result = runDockerURL(sc, p.Target)
		}

		if result.err != nil && len(result.stdout) == 0 {
			scans.MarkFailed(ctx, p.ScanID, result.err.Error(), result.log)
			log.Error("docker run failed", "err", result.err)
			return fmt.Errorf("%s docker run: %w", sc.Name, result.err)
		}

		parsed, parseErr := sc.Parse(result.stdout)
		if parseErr != nil {
			log.Warn("parse warning", "err", parseErr)
		}

		now := time.Now()
		inserted := 0
		for _, f := range parsed {
			sla := slaDeadlineFor(normalizeSeverity(f.Severity), now)
			var cveID, cweID *string
			if f.CVEID != "" {
				cveID = &f.CVEID
			}
			if f.CWEID != "" {
				cweID = &f.CWEID
			}
			norm := normalizeSeverity(f.Severity)

			suppressed, _ := policies.IsSuppressed(ctx, sc.Name, f.RuleID, f.FilePath)

			findingID, err := findings.Insert(ctx, repository.FindingInsert{
				ScanID: p.ScanID, Scanner: sc.Name, RuleID: f.RuleID,
				Title: f.Title, Description: f.Description,
				Severity: norm, FilePath: f.FilePath,
				LineStart: f.LineStart, LineEnd: f.LineEnd,
				CodeSnippet: f.CodeSnippet, Raw: f.Raw,
				SLADeadline: sla, CVEID: cveID, CWEID: cweID,
				Suppressed: suppressed,
			})
			if err != nil {
				log.Error("insert finding failed", "rule_id", f.RuleID, "err", err)
				continue
			}
			inserted++
			if err := findings.RefreshBatchCorrelation(ctx, findingID); err != nil {
				log.Warn("refresh batch correlation failed", "finding_id", findingID, "err", err)
			}
			if !suppressed {
				applyPolicies(ctx, policies, findingID, sc.Name, norm, f.RuleID, f.FilePath)
				enqueueAgentValidate(ctx, queue, findingID)
			}
		}

		log.Info("scan completed", "findings_parsed", len(parsed), "findings_inserted", inserted)

		var exitErrStr *string
		if result.err != nil {
			s := result.err.Error()
			exitErrStr = &s
		}
		return scans.MarkCompleted(ctx, p.ScanID, result.log, exitErrStr)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func cloneRepo(ctx context.Context, url, scanID string) (dir string, execLog string, err error) {
	dir = filepath.Join(os.TempDir(), "aspm-scan-"+scanID)
	start := time.Now()
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth=50", url, dir)
	out, cloneErr := cmd.CombinedOutput()
	execLog = buildSimpleLog("git clone --depth=50 "+url, out, nil, cloneErr, time.Since(start))
	if cloneErr != nil {
		return "", execLog, fmt.Errorf("git clone: %w\n%s", cloneErr, out)
	}
	return dir, execLog, nil
}

func buildDockerCmd(sc scanner.Scanner, args []string) *exec.Cmd {
	base := []string{"run", "--rm"}
	for k, v := range sc.Env {
		base = append(base, "-e", k+"="+v)
	}
	for _, vol := range sc.ExtraVolumes {
		base = append(base, "-v", vol)
	}
	if len(sc.Entrypoint) > 0 {
		base = append(base, "--entrypoint", sc.Entrypoint[0])
	}
	base = append(base, args...)
	return exec.Command("docker", base...)
}

func runDocker(sc scanner.Scanner, mountSrc string) runResult {
	args := []string{}
	if sc.MountDst != "" {
		args = append(args, "-v", fmt.Sprintf("%s:%s", mountSrc, sc.MountDst))
	}
	if sc.WorkDir != "" {
		args = append(args, "-w", sc.WorkDir)
	}
	args = append(args, sc.Image)
	args = append(args, sc.BuildArgs(sc.MountDst)...)
	return execute(sc, args)
}

func runDockerURL(sc scanner.Scanner, target string) runResult {
	args := []string{sc.Image}
	args = append(args, sc.BuildArgs(target)...)
	return execute(sc, args)
}

func execute(sc scanner.Scanner, dockerArgs []string) runResult {
	cmd := buildDockerCmd(sc, dockerArgs)
	cmdStr := "docker " + strings.Join(cmd.Args[1:], " ")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()

	return runResult{
		stdout: stdout.Bytes(),
		log:    buildSimpleLog(cmdStr, stdout.Bytes(), stderr.Bytes(), runErr, time.Since(start)),
		err:    runErr,
	}
}

func buildSimpleLog(cmdStr string, stdout, stderr []byte, err error, elapsed time.Duration) string {
	var b strings.Builder

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

var validSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
}

func normalizeSeverity(s string) string {
	if validSeverities[s] {
		return s
	}
	return "info"
}

func enqueueAgentValidate(ctx context.Context, queue *asynq.Client, findingID string) {
	payload, err := MarshalAgentValidatePayload(AgentValidatePayload{FindingID: findingID})
	if err != nil {
		slog.Warn("marshal agent:validate payload failed", "finding_id", findingID, "err", err)
		return
	}
	if _, err := queue.EnqueueContext(ctx, asynq.NewTask(TypeAgentValidate, payload)); err != nil {
		slog.Warn("enqueue agent:validate failed", "finding_id", findingID, "err", err)
	}
}

func slaDeadlineFor(severity string, now time.Time) *time.Time {
	var d time.Duration
	switch severity {
	case "critical":
		d = 24 * time.Hour
	case "high":
		d = 72 * time.Hour
	case "medium":
		d = 30 * 24 * time.Hour
	case "low":
		d = 90 * 24 * time.Hour
	default:
		return nil
	}
	t := now.Add(d)
	return &t
}

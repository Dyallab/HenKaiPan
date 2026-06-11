package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"aspm/internal/scanner"
)

// findingRow is a trimmed representation of a finding + scan target for backfill.
type findingRow struct {
	ID        string
	FilePath  string
	LineStart int
	LineEnd   int
	Target    string // repo URL from scans table
}

func run() error {
	dryRun := flag.Bool("dry-run", false, "print count of findings to process without modifying the database")
	batchSize := flag.Int("batch-size", 50, "number of updates per batch transaction")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL environment variable required")
	}

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()

	rows, err := pool.Query(ctx, `
		SELECT f.id, f.file_path, f.line_start, f.line_end, s.target
		FROM findings f
		JOIN scans s ON f.scan_id = s.id
		WHERE LENGTH(COALESCE(f.code_snippet, '')) < 10
		  AND f.status != 'archived'
	`)
	if err != nil {
		return fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()

	var findings []findingRow
	for rows.Next() {
		var f findingRow
		if err := rows.Scan(&f.ID, &f.FilePath, &f.LineStart, &f.LineEnd, &f.Target); err != nil {
			slog.Warn("scan row failed, skipping", "error", err)
			continue
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		slog.Info("no findings need backfill")
		return nil
	}

	if *dryRun {
		slog.Info("dry-run mode — no changes made", "findings_to_process", len(findings))
		return nil
	}

	// Group by repo URL to minimise git clones (one clone per repo).
	repoFindings := groupByTarget(findings)
	slog.Info("starting backfill", "repos", len(repoFindings), "total_findings", len(findings))

	var total atomic.Int64
	first := true

	for repoURL, repoFinds := range repoFindings {
		if !first {
			time.Sleep(time.Second) // rate limit between different repo clones
		}
		first = false

		if ctx.Err() != nil {
			slog.Info("interrupted", "processed", total.Load())
			return ctx.Err()
		}

		slog.Info("processing repo", "url", repoURL, "findings", len(repoFinds))

		cloneDir, err := os.MkdirTemp("", "backfill-*")
		if err != nil {
			slog.Warn("failed to create temp dir, skipping repo", "url", repoURL, "error", err)
			continue
		}

		if err := cloneRepo(ctx, repoURL, cloneDir); err != nil {
			slog.Warn("failed to clone repo, skipping", "url", repoURL, "error", err)
			os.RemoveAll(cloneDir)
			continue
		}

		// Process findings in batches of batchSize.
		for i := 0; i < len(repoFinds); i += *batchSize {
			end := i + *batchSize
			if end > len(repoFinds) {
				end = len(repoFinds)
			}
			batch := repoFinds[i:end]

			if err := processBatch(ctx, pool, cloneDir, batch); err != nil {
				slog.Error("batch processing failed", "offset", i, "error", err)
			}

			done := total.Add(int64(len(batch)))
			if done%100 == 0 {
				slog.Info("progress", "processed", done, "total", len(findings))
			}
		}

		os.RemoveAll(cloneDir)
	}

	done := total.Load()
	slog.Info("backfill complete", "total_processed", done)

	appendToLearnings(len(findings), done)

	return nil
}

// cloneRepo runs git clone --depth=1 for the given repo URL into dest.
func cloneRepo(ctx context.Context, repoURL, dest string) error {
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth=1", repoURL, dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone: %w\n%s", err, string(out))
	}
	return nil
}

// processBatch extracts snippets for a batch of findings and sends a
// pgx.Batch of UPDATE statements.
func processBatch(ctx context.Context, pool *pgxpool.Pool, cloneDir string, findings []findingRow) error {
	var batch pgx.Batch
	var skipped int

	for _, f := range findings {
		snippet, _, err := scanner.ExtractSnippet(cloneDir, f.FilePath, f.LineStart, f.LineEnd)
		if err != nil {
			slog.Warn("extract snippet failed", "id", f.ID, "file", f.FilePath, "error", err)
			skipped++
			continue
		}
		batch.Queue("UPDATE findings SET code_snippet = $1 WHERE id = $2", snippet, f.ID)
	}

	if batch.Len() == 0 {
		return nil
	}

	br := pool.SendBatch(ctx, &batch)
	defer br.Close()

	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("batch exec %d: %w", i, err)
		}
	}

	if skipped > 0 {
		slog.Debug("skipped findings in batch", "count", skipped)
	}
	return nil
}

// groupByTarget groups findings by their repo URL (s.target) so we clone
// each repo only once.
func groupByTarget(findings []findingRow) map[string][]findingRow {
	m := make(map[string][]findingRow, len(findings)/4)
	for _, f := range findings {
		m[f.Target] = append(m[f.Target], f)
	}
	return m
}

// appendToLearnings writes a summary entry to the finding-perf-plan learnings file.
func appendToLearnings(totalFindings int, processed int64) {
	path := ".omo/notepads/finding-perf-plan/learnings.md"
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		slog.Warn("failed to open learnings file", "path", path, "error", err)
		return
	}
	defer f.Close()

	entry := fmt.Sprintf("\n## %s: Backfill code_snippets\n\n- **What**: Backfilled %d/%d findings with code snippets via ExtractSnippet()\n- **Why**: Findings with empty or short snippets needed content from source repos\n- **Where**: `cmd/backfill-snippets/main.go` — CLI tool\n- **Learned**: Clone per-repo, batch UPDATEs in transactions of --batch-size\n", time.Now().Format("2006-01-02"), processed, totalFindings)
	if _, err := f.WriteString(entry); err != nil {
		slog.Warn("failed to write to learnings file", "error", err)
	}
}

func main() {
	if err := run(); err != nil {
		slog.Error("backfill failed", "error", err)
		os.Exit(1)
	}
}

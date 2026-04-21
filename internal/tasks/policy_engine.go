package tasks

import (
	"context"
	"log/slog"
	"strings"

	"aspm/internal/models"
	"aspm/internal/repository"
)

func applyPolicies(ctx context.Context, policies repository.PolicyRepository, findingID, scanner, severity, ruleID, filePath string) {
	active, err := policies.ListActive(ctx)
	if err != nil {
		slog.Error("policy engine: list active", "err", err)
		return
	}

	for _, p := range active {
		if conditionsMatch(p.Conditions, scanner, severity, ruleID, filePath) {
			if err := policies.ExecuteActions(ctx, findingID, p.Actions); err != nil {
				slog.Error("policy engine: execute actions", "policy_id", p.ID, "err", err)
			}
		}
	}
}

func conditionsMatch(conds []models.PolicyCondition, scanner, severity, ruleID, filePath string) bool {
	for _, c := range conds {
		var actual string
		switch c.Field {
		case "severity":
			actual = severity
		case "scanner":
			actual = scanner
		case "rule_id":
			actual = ruleID
		case "file_path":
			actual = filePath
		default:
			return false
		}
		switch c.Op {
		case "eq":
			if actual != c.Value {
				return false
			}
		case "contains":
			if !strings.Contains(actual, c.Value) {
				return false
			}
		default:
			return false
		}
	}
	return len(conds) > 0
}

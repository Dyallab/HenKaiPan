package handlers

import (
	"encoding/json"
	"net/http"

	"aspm/internal/ai"
	appknowledge "aspm/internal/knowledge"
)

func (h *Handler) AIRemediate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FindingID string `json:"finding_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.FindingID == "" {
		writeError(w, r, http.StatusBadRequest, "finding_id required")
		return
	}

	src, err := h.store.Findings.GetForRemediation(r.Context(), body.FindingID)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "finding not found")
		return
	}

	if cached, _ := h.store.Knowledge.FindByRuleID(r.Context(), src.RuleID); cached != nil {
		h.store.Findings.UpdateRemediationSlug(r.Context(), body.FindingID, cached.Slug)
		writeJSON(w, http.StatusOK, map[string]any{"article": cached, "cached": true})
		return
	}

	content, err := ai.GenerateRemediation(r.Context(), appknowledge.BuildRemediationRequest(src))
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "AI generation failed")
		return
	}

	articleDraft := appknowledge.BuildGeneratedArticle(src, content)
	a, err := h.store.Knowledge.Upsert(r.Context(), articleDraft)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"article": appknowledge.BuildGeneratedArticleFallback(articleDraft),
			"cached":  false,
		})
		return
	}

	h.store.Findings.UpdateRemediationSlug(r.Context(), body.FindingID, a.Slug)
	writeJSON(w, http.StatusOK, map[string]any{"article": a, "cached": false})
}

func (h *Handler) FindArticleForFinding(w http.ResponseWriter, r *http.Request) {
	ruleID := r.URL.Query().Get("rule_id")
	cweID := r.URL.Query().Get("cwe_id")
	if ruleID == "" && cweID == "" {
		writeError(w, r, http.StatusBadRequest, "rule_id or cwe_id required")
		return
	}

	a, err := h.store.Knowledge.FindByCWEOrRule(r.Context(), cweID, ruleID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "lookup failed")
		return
	}
	if a == nil {
		writeJSON(w, http.StatusOK, map[string]any{"found": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"found": true, "article": a})
}

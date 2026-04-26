package handlers

import (
	"encoding/json"
	"net/http"

	appknowledge "aspm/internal/knowledge"
	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) ListArticles(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	articles, err := h.store.Knowledge.List(r.Context(), repository.KnowledgeFilter{
		Search:  q.Get("q"),
		Scanner: q.Get("scanner"),
		Tag:     q.Get("tag"),
		CWEID:   q.Get("cwe_id"),
		RuleID:  q.Get("rule_id"),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list articles")
		return
	}
	writeJSON(w, http.StatusOK, articles)
}

func (h *Handler) GetArticle(w http.ResponseWriter, r *http.Request) {
	a, err := h.store.Knowledge.GetBySlug(r.Context(), chi.URLParam(r, "slug"))
	if err != nil {
		writeError(w, http.StatusNotFound, "article not found")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (h *Handler) CreateArticle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Title     string   `json:"title"`
		ContentMD string   `json:"content_md"`
		Tags      []string `json:"tags"`
		CWEIDs    []string `json:"cwe_ids"`
		RuleIDs   []string `json:"rule_ids"`
		Scanner   string   `json:"scanner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Title == "" {
		writeError(w, http.StatusBadRequest, "title required")
		return
	}
	a, err := h.store.Knowledge.Create(r.Context(), appknowledge.BuildCreateArticle(body.Title, body.ContentMD, body.Tags, body.CWEIDs, body.RuleIDs, body.Scanner))
	if err != nil {
		writeError(w, http.StatusConflict, "slug already exists or DB error: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (h *Handler) UpdateArticle(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	var body struct {
		Title     *string  `json:"title"`
		ContentMD *string  `json:"content_md"`
		Tags      []string `json:"tags"`
		CWEIDs    []string `json:"cwe_ids"`
		RuleIDs   []string `json:"rule_ids"`
		Scanner   *string  `json:"scanner"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := h.store.Knowledge.Update(r.Context(), slug, repository.ArticleUpdate{
		Title: body.Title, ContentMD: body.ContentMD,
		Tags: body.Tags, CWEIDs: body.CWEIDs, RuleIDs: body.RuleIDs, Scanner: body.Scanner,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update article")
		return
	}
	h.GetArticle(w, r)
}

func (h *Handler) DeleteArticle(w http.ResponseWriter, r *http.Request) {
	h.store.Knowledge.Delete(r.Context(), chi.URLParam(r, "slug"))
	w.WriteHeader(http.StatusNoContent)
}

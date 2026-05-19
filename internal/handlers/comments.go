package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"aspm/internal/auth"
	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) GetFindingComments(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")
	
	comments, err := h.store.Apps.GetFindingComments(r.Context(), findingID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to get comments")
		return
	}
	writeJSON(w, http.StatusOK, comments)
}

func (h *Handler) CreateFindingComment(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")
	
	claims := auth.GetClaims(r)
	if claims == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Content == "" {
		writeError(w, r, http.StatusBadRequest, "content required")
		return
	}

	comment, err := h.store.Apps.CreateFindingComment(r.Context(), repository.CommentCreate{
		FindingID: findingID,
		UserID:    claims.UserID,
		Content:   body.Content,
	})
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to create comment")
		return
	}
	writeJSON(w, http.StatusCreated, comment)
}

func (h *Handler) DeleteFindingComment(w http.ResponseWriter, r *http.Request) {
	commentID, err := strconv.ParseInt(chi.URLParam(r, "commentID"), 10, 64)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid comment ID")
		return
	}

	if err := h.store.Apps.DeleteFindingComment(r.Context(), commentID); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to delete comment")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

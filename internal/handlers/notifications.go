package handlers

import (
	"net/http"
	"strconv"

	"aspm/internal/auth"
	"aspm/internal/repository"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) GetNotifications(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit < 1 {
		limit = 20
	}

	claims := auth.GetClaims(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var readFilter *bool
	if r := q.Get("read"); r != "" {
		read := r == "true"
		readFilter = &read
	}

	notifications, total, err := h.store.Notifications.List(r.Context(), repository.NotificationFilter{
		UserID: claims.UserID,
		Read:   readFilter,
		Page:   page,
		Limit:  limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get notifications")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"notifications": notifications,
		"total":         total,
	})
}

func (h *Handler) MarkNotificationAsRead(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	claims := auth.GetClaims(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.store.Notifications.MarkAsRead(r.Context(), id, claims.UserID); err != nil {
		writeError(w, http.StatusNotFound, "notification not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) MarkAllNotificationsAsRead(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.store.Notifications.MarkAllAsRead(r.Context(), claims.UserID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to mark all as read")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) GetUnreadNotificationCount(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	count, err := h.store.Notifications.GetUnreadCount(r.Context(), claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get unread count")
		return
	}

	writeJSON(w, http.StatusOK, map[string]int{"count": count})
}

package handlers

import (
	"encoding/json"
	"net/http"

	"aspm/internal/repository"

	"github.com/hibiken/asynq"
)

type Handler struct {
	store       repository.Stores
	queue       *asynq.Client
	frontendURL string
}

func New(store repository.Stores, queue *asynq.Client, frontendURL string) *Handler {
	return &Handler{store: store, queue: queue, frontendURL: frontendURL}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

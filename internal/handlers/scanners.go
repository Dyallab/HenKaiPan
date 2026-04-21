package handlers

import (
	"net/http"
	"sort"

	"aspm/internal/scanner"
)

func (h *Handler) ListScanners(w http.ResponseWriter, r *http.Request) {
	infos := scanner.ListInfo()
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].Category != infos[j].Category {
			return infos[i].Category < infos[j].Category
		}
		return infos[i].Name < infos[j].Name
	})
	writeJSON(w, http.StatusOK, infos)
}

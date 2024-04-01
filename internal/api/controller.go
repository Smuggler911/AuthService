package api

import (
	"AuthService/internal/repository"
	"net/http"
)

func (h *Handler) loginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	repository.LoginUser(w, r)
}
func (h *Handler) updateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	repository.UpdateToken(w, r)
}

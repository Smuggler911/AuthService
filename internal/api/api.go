package api

import (
	"AuthService/internal/api/middleware"
	"net/http"
)

type Auth interface {
	loginUser(w http.ResponseWriter, r *http.Request)
	updateToken(w http.ResponseWriter, r *http.Request)
}
type Handler struct {
	Auth
}

func (h *Handler) HandleRequests() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", h.loginUser)
	mux.Handle("/update-token", middleware.RequireAuth(middleware.RequireRefresh(http.HandlerFunc(h.updateToken))))
	handler := h.addCorsHeaders(mux)
	return handler
}

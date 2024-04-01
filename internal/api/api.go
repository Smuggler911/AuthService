package api

import "net/http"

type Handler struct {
}

func (h *Handler) HandleRequests() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", h.loginUser)
	mux.HandleFunc("/update-token", h.updateToken)
	return mux
}

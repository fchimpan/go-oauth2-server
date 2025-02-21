package handler

import (
	"net/http"
	"time"

	"github.com/fchimpan/go-oauth2-server/internal/config"
	"github.com/fchimpan/go-oauth2-server/internal/store"
	"github.com/google/uuid"
)

func NewAuthorizeHandler(s *store.Store) *AuthorizeHandler {
	return &AuthorizeHandler{
		store: s,
	}
}

type AuthorizeHandler struct {
	store *store.Store
}

func (h *AuthorizeHandler) Handle(w http.ResponseWriter, r *http.Request) {
	// validate request
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("response_type") != "code" {
		http.Error(w, "Invalid response_type", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("client_id") != config.ClientID {
		http.Error(w, "Invalid client_id", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("redirect_uri") != config.RedirectURI {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("scope") != "" {
		http.Error(w, "Invalid scope", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") == "" {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")

	// 本来はここでユーザー認証チェック、認証済みならユーザーIDを取得する
	// authenticated, userID := isAuthenticated(r)
	// if !authenticated {
	// 	http.Redirect(w, r, "/login", http.StatusFound)
	// 	return
	// }

	authCode := uuid.New().String()
	v := store.NewStoreAuthCodeValue("user_id", clientID, redirectURI, state)
	if err := h.store.Set(r.Context(), authCode, v, 10*time.Minute); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// ref: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
	redirectURI = redirectURI + "?code=" + authCode + "&state=" + state
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

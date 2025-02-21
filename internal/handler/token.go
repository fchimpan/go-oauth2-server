package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/fchimpan/go-oauth2-server/internal/config"
	"github.com/fchimpan/go-oauth2-server/internal/store"
	"github.com/google/uuid"
)

type TokenHandler struct {
	store *store.Store
}

func NewTokenHandler(s *store.Store) *TokenHandler {
	return &TokenHandler{
		store: s,
	}
}

func (h *TokenHandler) Handle(w http.ResponseWriter, r *http.Request) {
	// validate request
	// ref: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusBadRequest)
		return
	}
	// Only support "authorization_code" grant type
	if r.PostFormValue("grant_type") != "authorization_code" {
		http.Error(w, "Invalid grant_type", http.StatusBadRequest)
		return
	}
	if r.PostFormValue("redirect_uri") != config.RedirectURI {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}
	code := r.PostFormValue("code")
	if code == "" {
		http.Error(w, "Invalid code", http.StatusBadRequest)
		return
	}

	v, err := h.store.GetAuthCode(r.Context(), code)
	if err != nil {
		http.Error(w, "Invalid code", http.StatusBadRequest)
		return
	}
	if v.RedirectURI != r.PostFormValue("redirect_uri") {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}
	// Authorization ヘッダーの検証
	hd := r.Header.Get("Authorization")
	if hd == "" {
		http.Error(w, "Invalid Authorization header", http.StatusBadRequest)
		return
	}
	clientSecret, err := getClientSecret(hd)
	if err != nil {
		http.Error(w, "Invalid Authorization header", http.StatusBadRequest)
		return
	}
	if clientSecret != config.ClientSecret {
		http.Error(w, "Invalid client_secret", http.StatusBadRequest)
		return
	}

	accessToken := uuid.New().String()
	refreshToken := uuid.New().String()
	issuedAt := time.Now()
	expiresIn := 3600
	expiresAt := issuedAt.Add(time.Duration(expiresIn) * time.Second)

	// store the token object
	tokenData := &store.TokenValue{
		ClientID:     config.ClientID,
		AccessToken:  accessToken,
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		IssuedAt:     time.Now(),
		TokenType:    "Bearer",
	}

	if err := h.store.Set(r.Context(), accessToken, tokenData, expiresAt.Sub(issuedAt)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"refresh_token": refreshToken,
	})
	log.Println("token issued")
}

func getClientSecret(authHeader string) (string, error) {
	// "Basic {base64_encoded_credentials}" でくることを期待
	// base64_encoded_credentials は "{client_id}:{client_secret}" を base64 エンコードしたもの
	// ref: https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		return "", fmt.Errorf("invalid Authorization header format")
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid base64 encoding")
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return "", fmt.Errorf("invalid credential format")
	}

	return credentials[1], nil
}

package jwt

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/AlexandrShapkin/go-auth-lab/internal/auth"
	"github.com/AlexandrShapkin/go-auth-lab/internal/storage"
)

const (
	SessionTokenCookieKey = "session_token"
)

type JWTAuth struct {
	SessionManager auth.SessionManager
	UserRepo       storage.UserRepo
}

// LoginHandler implements auth.Auth.
func (j *JWTAuth) LoginHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var creds auth.UserCreds

		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		u, err := j.UserRepo.FindByUsername(creds.Username)
		if err != nil || !u.IsValidUser(creds.Username, creds.Password) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		token, err := j.SessionManager.CreateSession(creds.Username)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     SessionTokenCookieKey,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Expires:  time.Now().Add(24 * time.Hour),
		})

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Login successful"))
	})
}

// ProtectedHandler implements auth.Auth.
func (j *JWTAuth) ProtectedHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionTokenCookieKey)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if _, err := j.SessionManager.ValidateSession(cookie.Value); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Access successfully granted!"))
	})
}

func NewAuth(secretKey []byte, userRepo storage.UserRepo) auth.Auth {
	return &JWTAuth{
		SessionManager: NewSessionManager(secretKey, userRepo),
		UserRepo:       userRepo,
	}
}

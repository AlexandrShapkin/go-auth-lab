package basic

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/AlexandrShapkin/go-auth-lab/internal/auth"
	"github.com/AlexandrShapkin/go-auth-lab/internal/storage"
)

const (
	Prefix = "Basic "
)

type BasicAuth struct {
	UserRepo storage.UserRepo
}

// LoginHandler implements auth.Auth.
func (b *BasicAuth) LoginHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("No authorization required! No return value"))
	})
}

// ProtectedHandler implements auth.Auth.
func (b *BasicAuth) ProtectedHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		if !strings.HasPrefix(auth, Prefix) {
			w.Header().Set("WWW-Authenticate", Prefix+`realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(auth[len(Prefix):])
		if err != nil {
			http.Error(w, "Invalid Authorization Header", http.StatusBadRequest)
			return
		}

		pair := strings.SplitN(string(payload), ":", 2)
		user, err := b.UserRepo.FindByUsername(pair[0])
		if len(pair) != 2 || err != nil || !user.IsValidUser(pair[0], pair[1]) {
			w.Header().Set("WWW-Authenticate", Prefix+`realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.Write([]byte("Access successfully granted!"))
	})
}

func NewAuth(userRepo storage.UserRepo) auth.Auth {
	return &BasicAuth{
		UserRepo: userRepo,
	}
}

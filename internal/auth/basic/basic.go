package basic

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/AlexandrShapkin/go-auth-lab/internal/auth"
)

const (
	Prefix = "Basic "
)

type BasicAuth struct{}

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
		if len(pair) != 2 || pair[0] != "username" || pair[1] != "password" {
			w.Header().Set("WWW-Authenticate", Prefix+`realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.Write([]byte("Access successfully granted!"))
	})
}

func NewAuth() auth.Auth {
	return &BasicAuth{}
}

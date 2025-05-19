package auth

import "net/http"

type Auth interface {
	LoginHandler() http.HandlerFunc
	ProtectedHandler() http.HandlerFunc
}
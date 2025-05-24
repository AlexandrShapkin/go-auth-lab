package auth

import "net/http"

type Auth interface {
	LoginHandler() http.HandlerFunc
	ProtectedHandler() http.HandlerFunc
}

type RefreshebleAuth interface {
	Auth
	RefreshHandler() http.HandlerFunc
}
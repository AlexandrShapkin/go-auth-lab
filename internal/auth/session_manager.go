package auth

import "github.com/AlexandrShapkin/go-auth-lab/internal/storage"

type SessionManager interface {
	CreateSession(string) (string, error)
	ValidateSession(string) (*storage.User, error)
}
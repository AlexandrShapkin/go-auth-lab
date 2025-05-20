package cookie

import (
	"fmt"

	"github.com/AlexandrShapkin/go-auth-lab/internal/auth"
	"github.com/AlexandrShapkin/go-auth-lab/internal/storage"
	"github.com/google/uuid"
)

type CookieSessionManager struct {
	Sessions map[string]string
	Repo     storage.UserRepo
}

// CreateSession implements auth.SessionManager.
func (c *CookieSessionManager) CreateSession(username string) (string, error) {
	token := uuid.NewString()
	c.Sessions[token] = username
	return token, nil
}

// ValidateSession implements auth.SessionManager.
func (c *CookieSessionManager) ValidateSession(token string) (*storage.User, error) {
	if username, ok := c.Sessions[token]; ok {
		return c.Repo.FindByUsername(username)
	}
	return nil, fmt.Errorf("invalid session token")
}

func NewSessionManager(repo storage.UserRepo) auth.SessionManager {
	return &CookieSessionManager{
		Sessions: make(map[string]string),
		Repo: repo,
	}
}

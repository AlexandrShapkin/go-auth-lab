package jwt

import (
	"fmt"
	"time"

	"github.com/AlexandrShapkin/go-auth-lab/internal/auth"
	"github.com/AlexandrShapkin/go-auth-lab/internal/storage"
	gojwt "github.com/golang-jwt/jwt/v5"
)

type JWTManager struct {
	SecretKey []byte
	Repo      storage.UserRepo
}

// CreateSession implements auth.SessionManager.
func (j *JWTManager) CreateSession(username string) (string, error) {
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256,
		gojwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: gojwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		})

	tokenString, err := token.SignedString(j.SecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateSession implements auth.SessionManager.
func (j *JWTManager) ValidateSession(tokenString string) (*storage.User, error) {
	token, err := gojwt.Parse(tokenString, func(t *gojwt.Token) (interface{}, error) {
		return j.SecretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	username, err := token.Claims.GetSubject()
	if err != nil {
		return nil, err
	}

	return j.Repo.FindByUsername(username)
}

func NewSessionManager(secretKey []byte, userRepo storage.UserRepo) auth.SessionManager {
	return &JWTManager{
		SecretKey: secretKey,
		Repo:      userRepo,
	}
}

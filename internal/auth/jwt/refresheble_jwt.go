package jwt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/AlexandrShapkin/go-auth-lab/internal/auth"
	"github.com/AlexandrShapkin/go-auth-lab/internal/storage"
	gojwt "github.com/golang-jwt/jwt/v5"
)

const (
	RefreshTokenCookieKey = "refresh_token"
	Prefix                = "Bearer "
)

type TokenResponase struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

type RefreshebleJWTAuth struct {
	AccessSecretKey []byte
	RefreshSecreKey []byte
	UserRepo        storage.UserRepo
}

// LoginHandler implements auth.RefreshebleAuth.
func (j *RefreshebleJWTAuth) LoginHandler() http.HandlerFunc {
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

		accessToken, refreshToken, err := j.createTokenPair(creds.Username)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     RefreshTokenCookieKey,
			Value:    refreshToken,
			Path:     "/refresh",
			HttpOnly: true,
			Expires:  time.Now().Add(7 * 24 * time.Hour),
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TokenResponase{
			AccessToken: accessToken,
			ExpiresIn:   30 * 60,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	})
}

// ProtectedHandler implements auth.RefreshebleAuth.
func (j *RefreshebleJWTAuth) ProtectedHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		if !strings.HasPrefix(auth, Prefix) {
			http.Error(w, "missing or malformed Authorization header", http.StatusUnauthorized)
			return
		}

		accessToken := strings.TrimPrefix(auth, Prefix)
		claims, err := j.ValidateAccessToken(accessToken)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		username, err := claims.GetSubject()
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if user, err := j.UserRepo.FindByUsername(username); err != nil || user == nil {
			http.Error(w, "user not found", http.StatusUnauthorized)
			return
		}

		w.Write([]byte("Access successfully granted!"))
	})
}

// RefreshHandler implements auth.RefreshebleAuth.
func (j *RefreshebleJWTAuth) RefreshHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(RefreshTokenCookieKey)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		refreshToken := cookie.Value

		claims, err := j.ValidateRefreshToken(refreshToken)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		username, err := claims.GetSubject()
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if user, err := j.UserRepo.FindByUsername(username); err != nil || user == nil {
			http.Error(w, "user not found", http.StatusUnauthorized)
			return
		}

		newAccess, newRefresh, err := j.createTokenPair(username)

		http.SetCookie(w, &http.Cookie{
			Name:     RefreshTokenCookieKey,
			Value:    newRefresh,
			Path:     "/refresh",
			HttpOnly: true,
			Expires:  time.Now().Add(7 * 24 * time.Hour),
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := TokenResponase{
			AccessToken: newAccess,
			ExpiresIn:   30 * 60,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	})
}

func NewRefreshebleAuth(accessSecretKey []byte, refreshSecretKey []byte, userRepo storage.UserRepo) auth.RefreshebleAuth {
	return &RefreshebleJWTAuth{
		AccessSecretKey: accessSecretKey,
		RefreshSecreKey: refreshSecretKey,
		UserRepo:        userRepo,
	}
}

func (j *RefreshebleJWTAuth) createTokenPair(username string) (string, string, error) {
	accessToken := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.RegisteredClaims{
		Subject:   username,
		ExpiresAt: gojwt.NewNumericDate(time.Now().Add(30 * 60 * time.Second)),
	})

	refreshToken := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.RegisteredClaims{
		Subject:   username,
		ExpiresAt: gojwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
	})

	accessTokenString, err := accessToken.SignedString(j.AccessSecretKey)
	if err != nil {
		return "", "", err
	}

	refreshTokenString, err := refreshToken.SignedString(j.RefreshSecreKey)
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}

func (j *RefreshebleJWTAuth) ValidateAccessToken(tokenString string) (gojwt.Claims, error) {
	token, err := gojwt.Parse(tokenString, func(t *gojwt.Token) (interface{}, error) {
		return j.AccessSecretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid access token")
	}

	return token.Claims, nil
}

func (j *RefreshebleJWTAuth) ValidateRefreshToken(tokenString string) (gojwt.Claims, error) {
	token, err := gojwt.Parse(tokenString, func(t *gojwt.Token) (interface{}, error) {
		return j.RefreshSecreKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invlid refresh token")
	}

	return token.Claims, nil
}

package jwt_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AlexandrShapkin/go-auth-lab/internal/auth/jwt"
	"github.com/AlexandrShapkin/go-auth-lab/internal/storage"
	gojwt "github.com/golang-jwt/jwt/v5"
)

func generateValidToken(secretKey []byte, username string) (string, error) {
	accessToken := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.RegisteredClaims{
		Subject:   username,
		ExpiresAt: gojwt.NewNumericDate(time.Now().Add(30 * 60 * time.Second)),
	})

	accessTokenString, err := accessToken.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return accessTokenString, nil
}

func generateInvalidToken(secretKey []byte, username string) (string, error) {
	accessToken := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.RegisteredClaims{
		Subject:   username,
		ExpiresAt: gojwt.NewNumericDate(time.Now().Add(30 * 60 * -time.Second)),
	})

	accessTokenString, err := accessToken.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return accessTokenString, nil
}

func TestRefreshebleLoginHandler(t *testing.T) {
	accessKey := []byte("access-256-bit-secret")
	refreshKey := []byte("refresh-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &jwt.RefreshebleJWTAuth{
		AccessSecretKey: accessKey,
		RefreshSecreKey: refreshKey,
		UserRepo:        repo,
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username": "username", "password": "password"}`))
	w := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	found := false
	valid := false
	path := false
	for _, c := range resp.Cookies() {
		if c.Name == jwt.RefreshTokenCookieKey {
			found = true
			if _, err := auth.ValidateRefreshToken(c.Value); err == nil {
				valid = true
			}
			if c.Path == "/refresh" {
				path = true
			}
			break
		}
	}

	if !found {
		t.Errorf("cookie '%s' not found in response", jwt.RefreshTokenCookieKey)
	} else {
		if !valid {
			t.Errorf("invalid refresh jwt token")
		} else if !path {
			t.Errorf("invalid refresh token cookie path")
		}
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("body read error: %v", err)
	}

	var tokenResponse jwt.TokenResponase
	if err := json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		t.Fatalf("body unmarshal error: %v", err)
	}

	claims, err := auth.ValidateAccessToken(tokenResponse.AccessToken)
	if err != nil {
		t.Fatalf("invalid access jwt token: %v", err)
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatalf("get expiration time error: %v", err)
	}

	claimsExp := exp.Time
	respExp := time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
	delta := respExp.Sub(claimsExp)
	if delta < -time.Second || delta > time.Second {
		t.Errorf("expiration time musmatch: claims 'exp' = %v, response 'exp' = %v (delta %v)", claimsExp, respExp, delta)
	}
}

func TestRefreshebleLoginHandler_InvalidBody(t *testing.T) {
	auth := &jwt.RefreshebleJWTAuth{}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("invalid body"))
	w := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}
}

func TestRefreshebleLoginHandler_InvalidUsername(t *testing.T) {
	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &jwt.RefreshebleJWTAuth{
		UserRepo: repo,
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username": "invalidUsername", "password": "password"}`))
	w := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	for _, c := range resp.Cookies() {
		if c.Name == jwt.RefreshTokenCookieKey {
			t.Errorf("unexpected cookie '%s' found in response", jwt.RefreshTokenCookieKey)
			break
		}
	}
}

func TestRefreshebleLoginHandler_InvalidPassword(t *testing.T) {
	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &jwt.RefreshebleJWTAuth{
		UserRepo: repo,
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username": "username", "password": "invalidPassword"}`))
	w := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	for _, c := range resp.Cookies() {
		if c.Name == jwt.RefreshTokenCookieKey {
			t.Errorf("unexpected cookie '%s' found in response", jwt.RefreshTokenCookieKey)
			break
		}
	}
}

func TestRefreshebleLoginHandler_InvalidUser(t *testing.T) {
	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  false,
			},
		},
	}

	auth := &jwt.RefreshebleJWTAuth{
		UserRepo: repo,
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username": "username", "password": "password"}`))
	w := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	for _, c := range resp.Cookies() {
		if c.Name == jwt.RefreshTokenCookieKey {
			t.Errorf("unexpected cookie '%s' found in response", jwt.RefreshTokenCookieKey)
			break
		}
	}
}

func TestRefreshebleProtectedHandler(t *testing.T) {
	accessKey := []byte("access-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &jwt.RefreshebleJWTAuth{
		AccessSecretKey: accessKey,
		UserRepo:        repo,
	}

	accessToken, err := generateValidToken(accessKey, "username")
	if err != nil {
		t.Fatalf("generate access token error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", jwt.Prefix+accessToken)
	w := httptest.NewRecorder()

	auth.ProtectedHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestRefreshebleProtectedHandler_MissedToken(t *testing.T) {
	accessKey := []byte("access-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &jwt.RefreshebleJWTAuth{
		AccessSecretKey: accessKey,
		UserRepo:        repo,
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	auth.ProtectedHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestRefreshebleProtectedHandler_MissedPrefix(t *testing.T) {
	accessKey := []byte("access-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &jwt.RefreshebleJWTAuth{
		AccessSecretKey: accessKey,
		UserRepo:        repo,
	}

	accessToken, err := generateValidToken(accessKey, "username")
	if err != nil {
		t.Fatalf("generate access token error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", accessToken)
	w := httptest.NewRecorder()

	auth.ProtectedHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestRefreshebleProtectedHandler_InvalidSubject(t *testing.T) {
	accessKey := []byte("access-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &jwt.RefreshebleJWTAuth{
		AccessSecretKey: accessKey,
		UserRepo:        repo,
	}

	accessToken, err := generateValidToken(accessKey, "invalidUsername")
	if err != nil {
		t.Fatalf("generate access token error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", jwt.Prefix+accessToken)
	w := httptest.NewRecorder()

	auth.ProtectedHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestRefreshebleProtectedHandler_InvalidToken(t *testing.T) {
	accessKey := []byte("access-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &jwt.RefreshebleJWTAuth{
		AccessSecretKey: accessKey,
		UserRepo:        repo,
	}

	accessToken, err := generateInvalidToken(accessKey, "username")
	if err != nil {
		t.Fatalf("generate access token error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", jwt.Prefix+accessToken)
	w := httptest.NewRecorder()

	auth.ProtectedHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestRefreshHandler(t *testing.T) {
	accessKey := []byte("access-256-bit-secret")
	refreshKey := []byte("refresh-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &jwt.RefreshebleJWTAuth{
		AccessSecretKey: accessKey,
		RefreshSecreKey: refreshKey,
		UserRepo:        repo,
	}

	refreshToken, err := generateValidToken(refreshKey, "username")
	if err != nil {
		t.Fatalf("generate access token error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  jwt.RefreshTokenCookieKey,
		Value: refreshToken,
	})
	w := httptest.NewRecorder()

	auth.RefreshHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	found := false
	valid := false
	path := false
	for _, c := range resp.Cookies() {
		if c.Name == jwt.RefreshTokenCookieKey {
			found = true
			if _, err := auth.ValidateRefreshToken(c.Value); err == nil {
				valid = true
			}
			if c.Path == "/refresh" {
				path = true
			}
			break
		}
	}

	if !found {
		t.Errorf("cookie '%s' not found in response", jwt.RefreshTokenCookieKey)
	} else {
		if !valid {
			t.Errorf("invalid refresh jwt token")
		} else if !path {
			t.Errorf("invalid refresh token cookie path")
		}
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("body read error: %v", err)
	}

	var tokenResponse jwt.TokenResponase
	if err := json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		t.Fatalf("body unmarshal error: %v", err)
	}

	claims, err := auth.ValidateAccessToken(tokenResponse.AccessToken)
	if err != nil {
		t.Fatalf("invalid access jwt token: %v", err)
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatalf("get expiration time error: %v", err)
	}

	claimsExp := exp.Time
	respExp := time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
	delta := respExp.Sub(claimsExp)
	if delta < -time.Second || delta > time.Second {
		t.Errorf("expiration time musmatch: claims 'exp' = %v, response 'exp' = %v (delta %v)", claimsExp, respExp, delta)
	}
}

func TestRefreshHandler_MissedToken(t *testing.T) {
	auth := &jwt.RefreshebleJWTAuth{}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	auth.RefreshHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	for _, c := range resp.Cookies() {
		if c.Name == jwt.RefreshTokenCookieKey {
			t.Errorf("unexpected cookie '%s' found in response", jwt.RefreshTokenCookieKey)
			break
		}
	}
}

func TestRefreshHandler_InvalidToken(t *testing.T) {
	refreshKey := []byte("refresh-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &jwt.RefreshebleJWTAuth{
		RefreshSecreKey: refreshKey,
		UserRepo:        repo,
	}

	refreshToken, err := generateInvalidToken(refreshKey, "username")
	if err != nil {
		t.Fatalf("generate access token error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  jwt.RefreshTokenCookieKey,
		Value: refreshToken,
	})
	w := httptest.NewRecorder()

	auth.RefreshHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	for _, c := range resp.Cookies() {
		if c.Name == jwt.RefreshTokenCookieKey {
			t.Errorf("unexpected cookie '%s' found in response", jwt.RefreshTokenCookieKey)
			break
		}
	}
}

func TestRefreshHandler_InvalidSubject(t *testing.T) {
	refreshKey := []byte("refresh-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &jwt.RefreshebleJWTAuth{
		RefreshSecreKey: refreshKey,
		UserRepo:        repo,
	}

	refreshToken, err := generateInvalidToken(refreshKey, "invalidUsername")
	if err != nil {
		t.Fatalf("generate access token error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  jwt.RefreshTokenCookieKey,
		Value: refreshToken,
	})
	w := httptest.NewRecorder()

	auth.RefreshHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	for _, c := range resp.Cookies() {
		if c.Name == jwt.RefreshTokenCookieKey {
			t.Errorf("unexpected cookie '%s' found in response", jwt.RefreshTokenCookieKey)
			break
		}
	}
}

package jwt_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AlexandrShapkin/go-auth-lab/internal/auth/jwt"
	"github.com/AlexandrShapkin/go-auth-lab/internal/storage"
)

type mockUser struct {
	username string
	password string
	isValid  bool
}

func (m *mockUser) IsValidUser(username, password string) bool {
	return m.isValid && m.username == username && m.password == password
}

func (m *mockUser) GetUsername() string {
	return m.username
}

func (m *mockUser) GetPassword() string {
	return m.password
}

type mockUserRepo struct {
	users map[string]storage.User
}

func (m *mockUserRepo) FindByUsername(username string) (storage.User, error) {
	user, ok := m.users[username]
	if !ok {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (m *mockUserRepo) Create(user storage.User) error {
	panic("unimplemented")
}

func (m *mockUserRepo) DeleteByUsername(username string) error {
	panic("unimplemented")
}

func TestLoginHandler(t *testing.T) {
	secretKey := []byte("your-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	sessionManager := jwt.NewSessionManager(secretKey, repo)

	auth := &jwt.JWTAuth{
		SessionManager: sessionManager,
		UserRepo:       repo,
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
	for _, c := range resp.Cookies() {
		if c.Name == jwt.SessionTokenCookieKey {
			found = true
			if _, err := sessionManager.ValidateSession(c.Value); err == nil {
				valid = true
			}
			break
		}
	}

	if !found {
		t.Errorf("cookie '%s' not found in response", jwt.SessionTokenCookieKey)
	} else if !valid {
		t.Errorf("invalid jwt token")
	}
}

func TestLoginHandler_InvalidBody(t *testing.T) {
	auth := &jwt.JWTAuth{}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("invalid body"))
	w := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}

	for _, c := range resp.Cookies() {
		if c.Name == jwt.SessionTokenCookieKey {
			t.Errorf("unexpected cookie '%s' found in response", jwt.SessionTokenCookieKey)
			break
		}
	}
}

func TestLoginHandler_InvalidUsername(t *testing.T) {
	secretKey := []byte("your-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &jwt.JWTAuth{
		SessionManager: jwt.NewSessionManager(secretKey, repo),
		UserRepo:       repo,
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username": "user", "password": "password"}`))
	w := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	for _, c := range resp.Cookies() {
		if c.Name == jwt.SessionTokenCookieKey {
			t.Errorf("unexpected cookie '%s' found in response", jwt.SessionTokenCookieKey)
			break
		}
	}
}

func TestLoginHandler_InvalidPassword(t *testing.T) {
	secretKey := []byte("your-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  false,
			},
		},
	}

	auth := &jwt.JWTAuth{
		SessionManager: jwt.NewSessionManager(secretKey, repo),
		UserRepo:       repo,
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username": "username", "password": "invalidPassword"}`))
	w := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	for _, c := range resp.Cookies() {
		if c.Name == jwt.SessionTokenCookieKey {
			t.Errorf("unexpected cookie '%s' found in response", jwt.SessionTokenCookieKey)
			break
		}
	}
}

func TestLoginHandler_InvalidUser(t *testing.T) {
	secretKey := []byte("your-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  false,
			},
		},
	}

	auth := &jwt.JWTAuth{
		SessionManager: jwt.NewSessionManager(secretKey, repo),
		UserRepo:       repo,
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username": "username", "password": "password"}`))
	w := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	for _, c := range resp.Cookies() {
		if c.Name == jwt.SessionTokenCookieKey {
			t.Errorf("unexpected cookie '%s' found in response", jwt.SessionTokenCookieKey)
			break
		}
	}
}

func TestProtectedHandler(t *testing.T) {
	secretKey := []byte("your-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	sessionManager := jwt.NewSessionManager(secretKey, repo)

	auth := &jwt.JWTAuth{
		SessionManager: sessionManager,
		UserRepo:       repo,
	}

	token, err := sessionManager.CreateSession("username")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  jwt.SessionTokenCookieKey,
		Value: token,
	})
	w := httptest.NewRecorder()

	auth.ProtectedHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestProtectedHandler_InvalidToken(t *testing.T) {
	secretKey := []byte("your-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	sessionManager := jwt.NewSessionManager(secretKey, repo)

	auth := &jwt.JWTAuth{
		SessionManager: sessionManager,
		UserRepo:       repo,
	}

	_, err := sessionManager.CreateSession("username")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  jwt.SessionTokenCookieKey,
		Value: "invalid_token",
	})
	w := httptest.NewRecorder()

	auth.ProtectedHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestProtectedHandler_MissingToken(t *testing.T) {
	secretKey := []byte("your-256-bit-secret")

	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	sessionManager := jwt.NewSessionManager(secretKey, repo)

	auth := &jwt.JWTAuth{
		SessionManager: sessionManager,
		UserRepo:       repo,
	}

	_, err := sessionManager.CreateSession("username")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	auth.ProtectedHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

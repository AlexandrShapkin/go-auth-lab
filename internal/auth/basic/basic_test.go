package basic_test

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AlexandrShapkin/go-auth-lab/internal/auth/basic"
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
	auth := &basic.BasicAuth{}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	if string(body) != "No authorization required! No return value" {
		t.Errorf("unexpected body: %s", string(body))
	}
}

func TestProtectedHandler_Success(t *testing.T) {
	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &basic.BasicAuth{UserRepo: repo}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	credentials := base64.StdEncoding.EncodeToString([]byte("username:password"))
	req.Header.Set("Authorization", basic.Prefix+credentials)
	w := httptest.NewRecorder()

	auth.ProtectedHandler().ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	if string(body) != "Access successfully granted!" {
		t.Errorf("unexpected body: %s", string(body))
	}
}

func TestProtectedHandler_MissingAuthHeader(t *testing.T) {
	auth := &basic.BasicAuth{}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	auth.ProtectedHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	if resp.Header.Get("WWW-Authenticate") != basic.Prefix+`realm="Restricted"` {
		t.Errorf("unexpected header %s", resp.Header.Get("WWW-Authenticate"))
	}
}

func TestProtectedHandler_BadBase64(t *testing.T) {
	auth := &basic.BasicAuth{}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", basic.Prefix+"notbase64")
	w := httptest.NewRecorder()

	auth.ProtectedHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}
}

func TestProtectedHandler_InvalidPassword(t *testing.T) {
	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &basic.BasicAuth{UserRepo: repo}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	credentials := base64.StdEncoding.EncodeToString([]byte("username:wrongpass"))
	req.Header.Set("Authorization", basic.Prefix+credentials)
	w := httptest.NewRecorder()

	auth.ProtectedHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	if resp.Header.Get("WWW-Authenticate") != basic.Prefix+`realm="Restricted"` {
		t.Errorf("unexpected header %s", resp.Header.Get("WWW-Authenticate"))
	}
}

func TestProtectedHandler_InvalidUsername(t *testing.T) {
	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  true,
			},
		},
	}

	auth := &basic.BasicAuth{UserRepo: repo}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	credentials := base64.StdEncoding.EncodeToString([]byte("wrongusername:password"))
	req.Header.Set("Authorization", basic.Prefix+credentials)
	w := httptest.NewRecorder()

	auth.ProtectedHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	if resp.Header.Get("WWW-Authenticate") != basic.Prefix+`realm="Restricted"` {
		t.Errorf("unexpected header %s", resp.Header.Get("WWW-Authenticate"))
	}
}

func TestProtectedHandler_InvalidUser(t *testing.T) {
	repo := &mockUserRepo{
		users: map[string]storage.User{
			"username": &mockUser{
				username: "username",
				password: "password",
				isValid:  false,
			},
		},
	}

	auth := &basic.BasicAuth{UserRepo: repo}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	credentials := base64.StdEncoding.EncodeToString([]byte("username:password"))
	req.Header.Set("Authorization", basic.Prefix+credentials)
	w := httptest.NewRecorder()

	auth.ProtectedHandler().ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	if resp.Header.Get("WWW-Authenticate") != basic.Prefix+`realm="Restricted"` {
		t.Errorf("unexpected header %s", resp.Header.Get("WWW-Authenticate"))
	}
}

package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"

	pauth "github.com/AlexandrShapkin/go-auth-lab/internal/auth"
	"github.com/AlexandrShapkin/go-auth-lab/internal/auth/basic"
	"github.com/AlexandrShapkin/go-auth-lab/internal/auth/cookie"
	"github.com/AlexandrShapkin/go-auth-lab/internal/auth/jwt"
	"github.com/AlexandrShapkin/go-auth-lab/internal/storage"
)

const (
	Addr      = ":8080"
	SecretKey = "your-256-bit-secret"

	HTTPBasicMode = "http_basic_auth"
	CookieMode    = "cookie_auth"
	JWTMode       = "jwt_auth"
	RJWTMode      = "refresheble_jwt_auth"
	NoAuthMode    = "no_auth"
)

type NoAuth struct{}

func (na *NoAuth) LoginHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("No authorization required! No return value"))
	})
}

func (na *NoAuth) ProtectedHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Access successfully granted!"))
	})
}

func NewNoAuth() Auth {
	return &NoAuth{}
}

type Auth interface {
	LoginHandler() http.HandlerFunc
	ProtectedHandler() http.HandlerFunc
}

func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Request", slog.String("method", r.Method), slog.String("path", r.URL.Path))
		next.ServeHTTP(w, r)
	})
}

func main() {
	mode := flag.String("mode", NoAuthMode, "Режим работы")

	flag.Parse()

	userRepo := storage.NewUserRepo()
	userRepo.Create(&storage.User{
		Username: "username",
		Password: "password",
	})

	var auth Auth

	switch *mode {
	case HTTPBasicMode:
		slog.Info("Selected HTTP Basic Mode")
		auth = basic.NewAuth(userRepo)
	case CookieMode:
		slog.Info("Selected Cookie Mode")
		auth = cookie.NewAuth(userRepo)
	case JWTMode:
		slog.Info("Selected JWT Mode")
		auth = jwt.NewAuth([]byte(SecretKey), userRepo)
	case RJWTMode:
		slog.Info("Selected Refresheble JWT Mode")
		auth = jwt.NewRefreshebleAuth([]byte(SecretKey), []byte(SecretKey), userRepo)
	default:
		slog.Info("Unknown mode, falling back to NoAuth")
		auth = NewNoAuth()
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/login", loggingMiddleware(auth.LoginHandler()))
	mux.HandleFunc("/protected", loggingMiddleware(auth.ProtectedHandler()))
	if rauth, ok := auth.(pauth.RefreshebleAuth); ok {
		mux.HandleFunc("/refresh", loggingMiddleware(rauth.RefreshHandler()))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	server := &http.Server{
		Addr:    Addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		slog.Info("Shutting down...")
		if err := server.Shutdown(context.Background()); err != nil {
			slog.Error("Server shutdown error", slog.String("error", err.Error()))
		}
	}()

	slog.Info("Starting server", slog.String("addr", Addr), slog.String("mode", *mode))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Server error", slog.String("error", err.Error()))
	}
}

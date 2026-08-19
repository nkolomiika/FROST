// Command api — HTTP API-сервер FROST (Go).
//
// Composition root: читает конфиг, поднимает логгер и chi-роутер, запускает
// HTTP-сервер с корректным graceful shutdown. Доменные адаптеры (Postgres, MinIO,
// RabbitMQ) подключаются здесь по мере переноса доменов из Python-бэкенда.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/nkolomiika/frost/config"
	httpadapter "github.com/nkolomiika/frost/internal/adapters/http"
	"github.com/nkolomiika/frost/internal/adapters/postgres/authrepo"
	"github.com/nkolomiika/frost/internal/adapters/security"
	"github.com/nkolomiika/frost/internal/app/auth"
	applog "github.com/nkolomiika/frost/internal/platform/log"
	"github.com/nkolomiika/frost/internal/platform/postgres"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	logger := applog.New(cfg.Debug)

	// Пул Postgres.
	pool, err := postgres.NewPool(context.Background(), cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pool.Close()

	// Контекст auth: security-адаптеры + репозиторий + use-cases + http-хендлер.
	jwtManager := security.NewJWTManager(cfg.JWTSecretKey, cfg.JWTAccessTokenExpireMinutes, cfg.JWTRefreshTokenExpireDays)
	cipher, err := security.NewSecretCipher(cfg.JWTSecretKey)
	if err != nil {
		return fmt.Errorf("cipher: %w", err)
	}
	authSvc := auth.NewService(
		authrepo.New(pool),
		jwtManager,
		cipher,
		auth.Config{
			RefreshTokenTTL:  time.Duration(cfg.JWTRefreshTokenExpireDays) * 24 * time.Hour,
			PasswordResetTTL: time.Duration(cfg.PasswordResetExpireHours) * time.Hour,
			AppBaseURL:       cfg.AppBaseURL,
			MailPreviewURL:   cfg.MailPreviewURL,
			SMTPHost:         cfg.SMTPHost,
			MailEnabled:      cfg.MailEnabled,
			Brand:            "FROST",
		},
		nil,
	)
	cookieCfg := httpadapter.CookieConfig{
		Secure:        cfg.CookieSecure,
		SameSite:      httpadapter.ParseSameSite(cfg.CookieSameSite),
		AccessMaxAge:  cfg.JWTAccessTokenExpireMinutes * 60,
		RefreshMaxAge: cfg.JWTRefreshTokenExpireDays * 24 * 60 * 60,
		TwoFAMaxAge:   5 * 60,
	}
	authHandler := httpadapter.NewAuthHandler(authSvc, cookieCfg, cfg.CSRFOrigins())

	router := httpadapter.NewRouter(httpadapter.Deps{Logger: logger, Auth: authHandler})

	addr := net.JoinHostPort(cfg.BackendHost, strconv.Itoa(cfg.BackendPort))
	srv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Слушаем сигналы завершения для graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("api listening", "addr", addr, "debug", cfg.Debug)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	logger.Info("api stopped cleanly")
	return nil
}

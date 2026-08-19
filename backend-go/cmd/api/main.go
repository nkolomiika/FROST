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
	applog "github.com/nkolomiika/frost/internal/platform/log"
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

	router := httpadapter.NewRouter(httpadapter.Deps{Logger: logger})

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

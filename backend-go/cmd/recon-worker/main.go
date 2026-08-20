// Command recon-worker — воркер рекон-фермы (DB-поллер таблицы host_farm_jobs).
// Порт worker/recon_worker.py, но БЕЗ RabbitMQ: host_farm_jobs — durable-очередь.
// Каждый тик: реклейм застрявших → выборка pending → атомарный claim → прогон.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nkolomiika/frost/config"
	"github.com/nkolomiika/frost/internal/adapters/postgres/reconrepo"
	"github.com/nkolomiika/frost/internal/app/recon"
	applog "github.com/nkolomiika/frost/internal/platform/log"
	"github.com/nkolomiika/frost/internal/platform/postgres"
)

const pollInterval = 5 * time.Second

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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if !cfg.ReconWorkerEnabled {
		logger.Warn("RECON_WORKER_ENABLED=false — recon-worker простаивает (задачи гоняет API inline)")
		<-ctx.Done()
		return nil
	}

	pool, err := postgres.NewPool(context.Background(), cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pool.Close()

	svc := recon.NewService(reconrepo.New(pool), recon.SettingsFromConfig(cfg), recon.ConfigFromConfig(cfg), logger)

	logger.Info("recon-worker запущен", "poll", pollInterval.String())
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		if err := svc.ProcessPending(ctx); err != nil {
			logger.Warn("process pending", "err", err)
		}
		select {
		case <-ctx.Done():
			logger.Info("recon-worker остановлен")
			return nil
		case <-ticker.C:
		}
	}
}

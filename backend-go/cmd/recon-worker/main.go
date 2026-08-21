// Command recon-worker — воркер рекон-фермы (DB-поллер таблицы host_farm_jobs).
// Порт worker/recon_worker.py, но БЕЗ RabbitMQ: host_farm_jobs — durable-очередь.
//
// Две НЕЗАВИСИМЫЕ дорожки-горутины поверх одного пула:
//   - «обычная» (regularPollInterval): все kind, кроме farm_run — держит
//     add-hosts/add-ips/port-scan отзывчивыми;
//   - «фермовая» (farmPollInterval): только farm_run, долгие прогоны.
//
// Так длинный прогон фермы (минуты) НЕ блокирует обычные задачи. Обе разделяют ctx
// и останавливаются на SIGINT/SIGTERM.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/nkolomiika/frost/config"
	"github.com/nkolomiika/frost/internal/adapters/postgres/reconrepo"
	"github.com/nkolomiika/frost/internal/app/recon"
	applog "github.com/nkolomiika/frost/internal/platform/log"
	"github.com/nkolomiika/frost/internal/platform/postgres"
	"log/slog"
)

const (
	regularPollInterval = 5 * time.Second
	farmPollInterval    = 5 * time.Second
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

	logger.Info("recon-worker запущен", "regular_poll", regularPollInterval.String(), "farm_poll", farmPollInterval.String())

	var wg sync.WaitGroup
	wg.Add(2)
	go runLane(ctx, &wg, logger, "regular", regularPollInterval, svc.ProcessPendingRegular)
	go runLane(ctx, &wg, logger, "farm", farmPollInterval, svc.ProcessPendingFarm)
	wg.Wait()

	logger.Info("recon-worker остановлен")
	return nil
}

// runLane крутит одну дорожку воркера: на каждом тике зовёт process, пока не придёт
// ctx.Done(). Дорожки независимы — падение одной итерации логируется, не роняя лейн.
func runLane(ctx context.Context, wg *sync.WaitGroup, logger *slog.Logger, name string, interval time.Duration, process func(context.Context) error) {
	defer wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := process(ctx); err != nil {
			logger.Warn("process pending", "lane", name, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

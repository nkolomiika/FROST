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
	"github.com/nkolomiika/frost/internal/adapters/leaksink"
	"github.com/nkolomiika/frost/internal/adapters/postgres/integrationsrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/leaksrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/reconrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/wordlistrepo"
	"github.com/nkolomiika/frost/internal/adapters/security"
	"github.com/nkolomiika/frost/internal/adapters/storage"
	"github.com/nkolomiika/frost/internal/app/integrations"
	"github.com/nkolomiika/frost/internal/app/leaks"
	"github.com/nkolomiika/frost/internal/app/recon"
	"github.com/nkolomiika/frost/internal/app/wordlists"
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

	reconRepo := reconrepo.New(pool)
	svc := recon.NewService(reconRepo, recon.SettingsFromConfig(cfg), recon.ConfigFromConfig(cfg), logger)

	// github secret-scan (kind=github_scan) на обычной дорожке пишет находки в
	// единое хранилище утечек и резолвит github_token из workspace-интеграций.
	cipher, err := security.NewSecretCipher(cfg.JWTSecretKey)
	if err != nil {
		return fmt.Errorf("cipher: %w", err)
	}
	integrationsSvc := integrations.NewService(integrationsrepo.New(pool), cipher)
	leaksSvc := leaks.NewService(leaksrepo.New(pool))
	svc.AttachLeaks(integrationsSvc, leaksink.New(leaksSvc))

	// Материализатор словарей: кастомный словарь (SubdomainWordlistID/EndpointsWordlistID)
	// стримится из MinIO во temp перед dnsx -w / ffuf -w. Без MinIO — только бандл-тиры
	// (fallback внутри resolveWordlist), кастомные id молча деградируют.
	var wlStorage wordlists.Storage = storage.Stub{}
	var archiveBlob recon.ArchiveBlobStore
	if cfg.MinioEndpoint != "" {
		ms, err := storage.NewMinio(cfg.MinioEndpoint, cfg.MinioAccessKey, cfg.MinioSecretKey, cfg.MinioBucketName, cfg.MinioUseSSL)
		if err != nil {
			return fmt.Errorf("minio: %w", err)
		}
		wlStorage = ms
		archiveBlob = ms
	} else {
		logger.Warn("MINIO_ENDPOINT пуст — кастомные словари фермы недоступны (только бандл-тиры)")
	}
	svc.AttachWordlists(wordlists.NewService(wordlistrepo.New(pool), wlStorage))

	// Автономная архивация холодного стейджинга в MinIO (см. archive.go). Свип —
	// отдельная дорожка воркера; без MinIO/при нулевом пороге — выключена.
	archiveEnabled := archiveBlob != nil && cfg.ReconArchiveStagingAfterDays > 0 && cfg.ReconArchiveSweepSeconds > 0
	if archiveEnabled {
		svc.AttachArchive(reconRepo, archiveBlob)
	}

	logger.Info("recon-worker запущен", "regular_poll", regularPollInterval.String(), "farm_poll", farmPollInterval.String(), "archive", archiveEnabled)

	var wg sync.WaitGroup
	wg.Add(2)
	go runLane(ctx, &wg, logger, "regular", regularPollInterval, svc.ProcessPendingRegular)
	go runLane(ctx, &wg, logger, "farm", farmPollInterval, svc.ProcessPendingFarm)
	if archiveEnabled {
		olderThan := time.Duration(cfg.ReconArchiveStagingAfterDays) * 24 * time.Hour
		batch := int32(cfg.ReconArchiveBatch)
		wg.Add(1)
		go runLane(ctx, &wg, logger, "archive", time.Duration(cfg.ReconArchiveSweepSeconds)*time.Second, func(c context.Context) error {
			n, err := svc.ArchiveColdStaging(c, olderThan, batch)
			if err == nil && n > 0 {
				logger.Info("staging archived", "runs", n)
			}
			return err
		})
	}
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

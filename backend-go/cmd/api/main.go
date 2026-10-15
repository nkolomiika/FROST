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
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/config"
	"github.com/nkolomiika/frost/db"
	httpadapter "github.com/nkolomiika/frost/internal/adapters/http"
	"github.com/nkolomiika/frost/internal/adapters/leaksink"
	"github.com/nkolomiika/frost/internal/adapters/postgres/agenttokenrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/auditrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/authrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/integrationsrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/inventoryrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/leaksrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/notificationsrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/projectsrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/reconrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/reportrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/adapters/postgres/usersrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/vulnsrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/wordlistrepo"
	"github.com/nkolomiika/frost/internal/adapters/security"
	"github.com/nkolomiika/frost/internal/adapters/storage"
	"github.com/nkolomiika/frost/internal/app/agenttokens"
	"github.com/nkolomiika/frost/internal/app/audit"
	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/app/integrations"
	"github.com/nkolomiika/frost/internal/app/inventory"
	"github.com/nkolomiika/frost/internal/app/leaks"
	"github.com/nkolomiika/frost/internal/app/notifications"
	"github.com/nkolomiika/frost/internal/app/projects"
	"github.com/nkolomiika/frost/internal/app/recon"
	"github.com/nkolomiika/frost/internal/app/report"
	"github.com/nkolomiika/frost/internal/app/users"
	"github.com/nkolomiika/frost/internal/app/vulns"
	"github.com/nkolomiika/frost/internal/app/wordlists"
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

	// Применяем миграции схемы (Go-API сам создаёт схему).
	if err := db.RunMigrations(cfg.DatabaseURL); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	logger.Info("migrations applied")

	// Пул Postgres.
	pool, err := postgres.NewPool(context.Background(), cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pool.Close()

	if err := bootstrapAdmin(context.Background(), pool, cfg, logger); err != nil {
		logger.Warn("bootstrap admin", "err", err)
	}

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

	// Контекст audit (просмотр журнала, admin-only).
	auditHandler := httpadapter.NewAuditHandler(audit.NewService(auditrepo.New(pool)), authSvc)

	// Контекст agenttokens (управление токенами /api/v1/agent-tokens).
	agentSvc := agenttokens.NewService(agenttokenrepo.New(pool), nil)
	agentTokenHandler := httpadapter.NewAgentTokenHandler(agentSvc, authSvc, cfg.CSRFOrigins())

	// Общий сервис projects (доступ к проектам + сам контекст). Переиспользуется
	// контекстами inventory/vulns для require_project_access.
	projectsSvc := projects.NewService(projectsrepo.New(pool), cipher, nil)
	projectsHandler := httpadapter.NewProjectsHandler(projectsSvc, authSvc, cfg.CSRFOrigins())

	// Объектное хранилище (MinIO) для файлов/аватаров/словарей; stub, если не
	// сконфигурировано. Один и тот же клиент реализует порты Storage всех контекстов.
	var fileStorage vulns.Storage
	var wlStorage wordlists.Storage
	var archiveBlob recon.ArchiveBlobStore
	if cfg.MinioEndpoint != "" {
		ms, err := storage.NewMinio(cfg.MinioEndpoint, cfg.MinioAccessKey, cfg.MinioSecretKey, cfg.MinioBucketName, cfg.MinioUseSSL)
		if err != nil {
			return fmt.Errorf("minio: %w", err)
		}
		if err := ms.EnsureBucket(context.Background()); err != nil {
			logger.Warn("minio bucket ensure failed", "err", err)
		}
		fileStorage = ms
		wlStorage = ms
		archiveBlob = ms
	} else {
		fileStorage = storage.Stub{}
		wlStorage = storage.Stub{}
		logger.Warn("MINIO_ENDPOINT пуст — файловое хранилище отключено (stub)")
	}

	// Контекст inventory (hosts/ips/ports/services/endpoints).
	inventorySvc := inventory.NewService(inventoryrepo.New(pool), nil)
	inventoryHandler := httpadapter.NewInventoryHandler(inventorySvc, projectsSvc, authSvc, cfg.CSRFOrigins())

	// Контекст vulns (уязвимости/CVSS/assets/комментарии/файлы).
	vulnsSvc := vulns.NewService(vulnsrepo.New(pool), fileStorage, cfg.MinioBucketName)
	vulnsHandler := httpadapter.NewVulnsHandler(vulnsSvc, projectsSvc, authSvc, cfg.CSRFOrigins())

	// Контекст notifications (лента уведомлений).
	notificationsHandler := httpadapter.NewNotificationsHandler(notifications.NewService(notificationsrepo.New(pool)), authSvc, cfg.CSRFOrigins())

	// Контекст integrations (workspace-level API-ключи, admin-only) + leaks
	// (единое хранилище утечек). Оба переиспользуют cipher project-кред.
	integrationsSvc := integrations.NewService(integrationsrepo.New(pool), cipher)
	integrationsHandler := httpadapter.NewIntegrationsHandler(integrationsSvc, authSvc, cfg.CSRFOrigins())
	leaksSvc := leaks.NewService(leaksrepo.New(pool))

	// Контекст recon (ферма + scanner + js-files). Подключаем резолвер интеграций
	// и приёмник утечек — для github secret-scan (kind=github_scan).
	reconRepo := reconrepo.New(pool)
	reconSvc := recon.NewService(reconRepo, recon.SettingsFromConfig(cfg), recon.ConfigFromConfig(cfg), logger)
	// Ключи источников — из окружения (.env.prod), не из БД: раздел Integrations в
	// вебке удалён, всё через env. См. recon.IntegrationResolverFromConfig.
	reconSvc.AttachLeaks(recon.IntegrationResolverFromConfig(cfg), leaksink.New(leaksSvc))
	// Регидрация заархивированного стейджинга при открытии отчёта (см. archive.go).
	if archiveBlob != nil {
		reconSvc.AttachArchive(reconRepo, archiveBlob)
	}
	reconHandler := httpadapter.NewReconHandler(reconSvc, projectsSvc, authSvc, cfg.CSRFOrigins(), cfg.FarmMaxRawBytes)

	// Контекст wordlists (кастомные словари фермы, workspace-level, файлы в MinIO).
	// Материализатор словарей подключаем в recon — брут/ffuf получают путь через него.
	wordlistsSvc := wordlists.NewService(wordlistrepo.New(pool), wlStorage)
	reconSvc.AttachWordlists(wordlistsSvc)
	wordlistHandler := httpadapter.NewWordlistHandler(wordlistsSvc, authSvc, cfg.CSRFOrigins())
	leaksHandler := httpadapter.NewLeaksHandler(reconSvc, leaksSvc, projectsSvc, authSvc, cfg.CSRFOrigins(), cfg.FarmMaxRawBytes)

	// Контекст agent-tokens v2 (/api/v2 bearer API). После recon/leaks — v2 отдаёт
	// read по IP/JS/утечкам (scopes assets:read / leaks:read).
	agentV2Handler := httpadapter.NewAgentV2Handler(agentSvc, projectsSvc, inventorySvc, vulnsSvc, reconSvc, leaksSvc)

	// Контекст reports (Python-sidecar, интерим).
	reportsHandler := httpadapter.NewReportsHandler(report.NewService(reportrepo.New(pool), fileStorage, cfg.ReportsSidecarURL, cfg.ReportsSidecarToken), projectsSvc, authSvc, cfg.CSRFOrigins())

	// Контекст users (профиль/2FA/аватары/инвайты, admin-управление).
	usersHandler := httpadapter.NewUsersHandler(
		users.NewService(usersrepo.New(pool), cipher, fileStorage, users.Config{
			AppBaseURL: cfg.AppBaseURL, MailPreviewURL: cfg.MailPreviewURL, SMTPHost: cfg.SMTPHost,
			MailEnabled: cfg.MailEnabled, Brand: "FROST", MinioBucketName: cfg.MinioBucketName,
			InviteTokenExpireHours: cfg.InviteTokenExpireHours, ReactivationExpireHours: cfg.ReactivationExpireHours,
		}, nil),
		authSvc, cfg.CSRFOrigins())

	router := httpadapter.NewRouter(httpadapter.Deps{Logger: logger, Auth: authHandler, Audit: auditHandler, AgentTokens: agentTokenHandler, Projects: projectsHandler, Inventory: inventoryHandler, Vulns: vulnsHandler, Users: usersHandler, AgentV2: agentV2Handler, Notifications: notificationsHandler, Recon: reconHandler, Reports: reportsHandler, Integrations: integrationsHandler, Leaks: leaksHandler, Wordlists: wordlistHandler})

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

// bootstrapAdmin создаёт стартового администратора при пустой таблице users
// (порт UserService.bootstrap_admin — Go-API поднимается на чистой схеме).
func bootstrapAdmin(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, logger *slog.Logger) error {
	q := sqlc.New(pool)
	exists, err := q.UsernameExists(ctx, cfg.InitialAdminUsername)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	total, err := q.CountUsers(ctx)
	if err != nil {
		return err
	}
	if total > 0 {
		return nil
	}
	hash, err := security.HashPassword(cfg.InitialAdminPassword)
	if err != nil {
		return err
	}
	if _, err := q.CreateUser(ctx, sqlc.CreateUserParams{
		Username:     cfg.InitialAdminUsername,
		Email:        strings.ToLower(cfg.InitialAdminEmail),
		FullName:     pgtype.Text{String: "Administrator", Valid: true},
		PasswordHash: hash,
		Role:         sqlc.UserRoleADMIN,
		ProjectRole:  sqlc.ProjectRolePENTESTER,
		IsActive:     true,
	}); err != nil {
		return err
	}
	logger.Info("initial admin created", "username", cfg.InitialAdminUsername)
	return nil
}

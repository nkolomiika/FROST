// Command mail-worker — воркер mail-outbox (DB-поллер таблицы mail_jobs).
// Порт worker/mail_worker.py: рендер по template+payload и SMTP-отправка.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nkolomiika/frost/config"
	"github.com/nkolomiika/frost/internal/adapters/mail"
	"github.com/nkolomiika/frost/internal/adapters/postgres/mailerrepo"
	"github.com/nkolomiika/frost/internal/app/mailer"
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

	if !cfg.MailEnabled {
		logger.Warn("MAIL_ENABLED=false — mail-worker простаивает")
		<-ctx.Done()
		return nil
	}

	pool, err := postgres.NewPool(context.Background(), cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pool.Close()

	sender := mail.NewSender(mail.SMTPConfig{
		Host: cfg.SMTPHost, Port: cfg.SMTPPort, Username: cfg.SMTPUsername, Password: cfg.SMTPPassword,
		UseTLS: cfg.SMTPUseTLS, UseSSL: cfg.SMTPUseSSL, Timeout: time.Duration(cfg.SMTPTimeoutSecs * float64(time.Second)),
		FromEmail: cfg.SMTPFromEmail, FromName: cfg.SMTPFromName, AuthMethod: cfg.SMTPAuthMethod,
		OAuth: mail.OAuthConfig{
			ClientID: cfg.GoogleOAuthID, ClientSecret: cfg.GoogleOAuthSecret, RefreshToken: cfg.GoogleOAuthRefresh,
			TokenURI: cfg.GoogleOAuthTokenURI, Timeout: time.Duration(cfg.SMTPTimeoutSecs * float64(time.Second)),
		},
	})
	svc := mailer.NewService(mailerrepo.New(pool), sender, int32(cfg.MailMaxAttempts), logger)

	logger.Info("mail-worker запущен", "poll", pollInterval.String())
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		if err := svc.ProcessPending(ctx); err != nil {
			logger.Warn("process pending", "err", err)
		}
		select {
		case <-ctx.Done():
			logger.Info("mail-worker остановлен")
			return nil
		case <-ticker.C:
		}
	}
}

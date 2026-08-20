// Package config загружает настройки приложения из переменных окружения.
// Зеркало app/config.py (pydantic-settings) Python-бэкенда: те же имена env,
// чтобы Go- и Python-сервисы читали один .env во время миграции.
package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// Config — полный набор настроек. Значения по умолчанию совпадают с Python-версией.
type Config struct {
	// --- База данных ---
	// DATABASE_URL у Python — SQLAlchemy-URL (postgresql+asyncpg://...).
	// pgx понимает обычный postgres:// — нормализуем в Normalize().
	DatabaseURL string `env:"DATABASE_URL,required"`

	// --- JWT / сессии ---
	JWTSecretKey                string `env:"JWT_SECRET_KEY,required"`
	JWTAccessTokenExpireMinutes int    `env:"JWT_ACCESS_TOKEN_EXPIRE_MINUTES" envDefault:"30"`
	JWTRefreshTokenExpireDays   int    `env:"JWT_REFRESH_TOKEN_EXPIRE_DAYS" envDefault:"30"`

	// --- HTTP-сервер ---
	BackendHost        string `env:"BACKEND_HOST" envDefault:"0.0.0.0"`
	BackendPort        int    `env:"BACKEND_PORT" envDefault:"8000"`
	Debug              bool   `env:"DEBUG" envDefault:"false"`
	BackendCORSOrigins string `env:"BACKEND_CORS_ORIGINS" envDefault:"https://localhost:3000,https://127.0.0.1:3000"`
	CSRFAllowedOrigins string `env:"CSRF_ALLOWED_ORIGINS" envDefault:"https://localhost:3000,https://127.0.0.1:3000"`

	// --- Cookie ---
	CookieSecure   bool   `env:"COOKIE_SECURE" envDefault:"true"`
	CookieSameSite string `env:"COOKIE_SAMESITE" envDefault:"strict"`

	// --- Стартовый администратор ---
	InitialAdminUsername string `env:"INITIAL_ADMIN_USERNAME" envDefault:"admin"`
	InitialAdminEmail    string `env:"INITIAL_ADMIN_EMAIL" envDefault:"admin@example.com"`
	InitialAdminPassword string `env:"INITIAL_ADMIN_PASSWORD" envDefault:"admin"`

	// --- MinIO ---
	MinioEndpoint   string `env:"MINIO_ENDPOINT"`
	MinioAccessKey  string `env:"MINIO_ACCESS_KEY"`
	MinioSecretKey  string `env:"MINIO_SECRET_KEY"`
	MinioBucketName string `env:"MINIO_BUCKET_NAME"`
	MinioUseSSL     bool   `env:"MINIO_USE_SSL" envDefault:"false"`

	// --- RabbitMQ / почта ---
	RabbitMQURL         string  `env:"RABBITMQ_URL" envDefault:"amqp://guest:guest@rabbitmq/"`
	MailQueueName       string  `env:"MAIL_QUEUE_NAME" envDefault:"pcf.mail"`
	MailEnabled         bool    `env:"MAIL_ENABLED" envDefault:"true"`
	ReconQueueName      string  `env:"RECON_QUEUE_NAME" envDefault:"recon"`
	SMTPHost            string  `env:"SMTP_HOST" envDefault:"mailpit"`
	MailPreviewURL      string  `env:"MAIL_PREVIEW_URL" envDefault:"http://localhost:8025"`
	MailMaxAttempts     int     `env:"MAIL_MAX_ATTEMPTS" envDefault:"5"`
	SMTPPort            int     `env:"SMTP_PORT" envDefault:"1025"`
	SMTPUsername        string  `env:"SMTP_USERNAME"`
	SMTPPassword        string  `env:"SMTP_PASSWORD"`
	SMTPUseTLS          bool    `env:"SMTP_USE_TLS" envDefault:"false"`
	SMTPUseSSL          bool    `env:"SMTP_USE_SSL" envDefault:"false"`
	SMTPTimeoutSecs     float64 `env:"SMTP_TIMEOUT_SECONDS" envDefault:"20.0"`
	SMTPFromEmail       string  `env:"SMTP_FROM_EMAIL" envDefault:"noreply@example.com"`
	SMTPFromName        string  `env:"SMTP_FROM_NAME" envDefault:"PCF"`
	SMTPAuthMethod      string  `env:"SMTP_AUTH_METHOD" envDefault:"password"`
	GoogleOAuthID       string  `env:"GOOGLE_OAUTH_CLIENT_ID"`
	GoogleOAuthSecret   string  `env:"GOOGLE_OAUTH_CLIENT_SECRET"`
	GoogleOAuthRefresh  string  `env:"GOOGLE_OAUTH_REFRESH_TOKEN"`
	GoogleOAuthTokenURI string  `env:"GOOGLE_OAUTH_TOKEN_URI" envDefault:"https://oauth2.googleapis.com/token"`

	// --- Ссылки в письмах и сроки жизни токенов (часы) ---
	AppBaseURL               string `env:"APP_BASE_URL" envDefault:"https://localhost:3000"`
	InviteTokenExpireHours   int    `env:"INVITE_TOKEN_EXPIRE_HOURS" envDefault:"168"`
	PasswordResetExpireHours int    `env:"PASSWORD_RESET_EXPIRE_HOURS" envDefault:"2"`
	ReactivationExpireHours  int    `env:"REACTIVATION_EXPIRE_HOURS" envDefault:"24"`
}

// Load читает .env (если есть) и переменные окружения в Config.
func Load() (*Config, error) {
	// .env не обязателен: в проде переменные приходят из окружения контейнера.
	_ = godotenv.Load()

	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parse env: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.Normalize()
	return cfg, nil
}

func (c *Config) validate() error {
	if len(c.JWTSecretKey) < 32 {
		return errors.New("JWT_SECRET_KEY должен содержать минимум 32 символа")
	}
	return nil
}

// Normalize приводит SQLAlchemy-URL к виду, понятному pgx.
func (c *Config) Normalize() {
	c.DatabaseURL = strings.Replace(c.DatabaseURL, "postgresql+asyncpg://", "postgres://", 1)
	c.DatabaseURL = strings.Replace(c.DatabaseURL, "postgresql://", "postgres://", 1)
}

// CORSOrigins возвращает список разрешённых CORS-источников.
func (c *Config) CORSOrigins() []string { return splitCSV(c.BackendCORSOrigins) }

// CSRFOrigins возвращает список разрешённых Origin для CSRF-проверки.
func (c *Config) CSRFOrigins() []string { return splitCSV(c.CSRFAllowedOrigins) }

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

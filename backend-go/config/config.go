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

	// --- Reports sidecar (интерим: Python word_builder за внутренним HTTP) ---
	ReportsSidecarURL   string `env:"REPORTS_SIDECAR_URL" envDefault:"http://report-sidecar:8100"`
	ReportsSidecarToken string `env:"REPORTS_SIDECAR_TOKEN"`

	// --- Ссылки в письмах и сроки жизни токенов (часы) ---
	AppBaseURL               string `env:"APP_BASE_URL" envDefault:"https://localhost:3000"`
	InviteTokenExpireHours   int    `env:"INVITE_TOKEN_EXPIRE_HOURS" envDefault:"168"`
	PasswordResetExpireHours int    `env:"PASSWORD_RESET_EXPIRE_HOURS" envDefault:"2"`
	ReactivationExpireHours  int    `env:"REACTIVATION_EXPIRE_HOURS" envDefault:"24"`

	// --- Recon-ферма: серверный пробив вставленных списков хостов и IP ---
	// Зеркало config.py §5. float-секунды парсим как float64 (совпадает с .env).
	FarmMaxTargets               int     `env:"FARM_MAX_TARGETS" envDefault:"256"`
	FarmMaxPortsPerHost          int     `env:"FARM_MAX_PORTS_PER_HOST" envDefault:"32"`
	FarmProbeTimeoutSeconds      float64 `env:"FARM_PROBE_TIMEOUT_SECONDS" envDefault:"8.0"`
	FarmMaxConcurrency           int     `env:"FARM_MAX_CONCURRENCY" envDefault:"20"`
	FarmMaxRawBytes              int     `env:"FARM_MAX_RAW_BYTES" envDefault:"262144"`
	FarmAllowPrivateTargets      bool    `env:"FARM_ALLOW_PRIVATE_TARGETS" envDefault:"false"`
	FarmReverseDNSEnabled        bool    `env:"FARM_REVERSE_DNS_ENABLED" envDefault:"true"`
	FarmIPResolveHostsEnabled    bool    `env:"FARM_IP_RESOLVE_HOSTS_ENABLED" envDefault:"true"`
	FarmHostResolveIPsEnabled    bool    `env:"FARM_HOST_RESOLVE_IPS_ENABLED" envDefault:"true"`
	FarmReverseDNSTimeoutSeconds float64 `env:"FARM_REVERSE_DNS_TIMEOUT_SECONDS" envDefault:"3.0"`

	ReconWorkerEnabled   bool `env:"RECON_WORKER_ENABLED" envDefault:"true"`
	ReconMaxAttempts     int  `env:"RECON_MAX_ATTEMPTS" envDefault:"3"`
	ReconStaleJobSeconds int  `env:"RECON_STALE_JOB_SECONDS" envDefault:"1800"`
	ReconResultMaxItems  int  `env:"RECON_RESULT_MAX_ITEMS" envDefault:"200"`

	// --- Ферма JS ---
	JSFarmMaxFilesPerHost        int     `env:"JS_FARM_MAX_FILES_PER_HOST" envDefault:"50"`
	JSFarmMaxFileBytes           int     `env:"JS_FARM_MAX_FILE_BYTES" envDefault:"5000000"`
	JSFarmDownloadTimeoutSeconds float64 `env:"JS_FARM_DOWNLOAD_TIMEOUT_SECONDS" envDefault:"15.0"`
	JSFarmMaxConcurrency         int     `env:"JS_FARM_MAX_CONCURRENCY" envDefault:"10"`
	JSFarmMaxTotalFiles          int     `env:"JS_FARM_MAX_TOTAL_FILES" envDefault:"500"`

	// --- Определение технологий/CDN веб-порта ---
	ServicesDetectEnabled        bool    `env:"SERVICES_DETECT_ENABLED" envDefault:"true"`
	ServicesDetectEngine         string  `env:"SERVICES_DETECT_ENGINE" envDefault:"httpx"`
	ServicesHttpxBin             string  `env:"SERVICES_HTTPX_BIN" envDefault:"httpx-pd"`
	ServicesWhatwebBin           string  `env:"SERVICES_WHATWEB_BIN" envDefault:"whatweb"`
	ServicesDetectTimeoutSeconds float64 `env:"SERVICES_DETECT_TIMEOUT_SECONDS" envDefault:"20.0"`
	ServicesMaxConcurrency       int     `env:"SERVICES_MAX_CONCURRENCY" envDefault:"6"`

	// --- Scanner: поддомены ---
	SubsCrtshEnabled            bool    `env:"SUBS_CRTSH_ENABLED" envDefault:"true"`
	SubsCrtshTimeoutSeconds     float64 `env:"SUBS_CRTSH_TIMEOUT_SECONDS" envDefault:"30.0"`
	SubsSubfinderEnabled        bool    `env:"SUBS_SUBFINDER_ENABLED" envDefault:"true"`
	SubsSubfinderBin            string  `env:"SUBS_SUBFINDER_BIN" envDefault:"subfinder"`
	SubsSubfinderTimeoutSeconds float64 `env:"SUBS_SUBFINDER_TIMEOUT_SECONDS" envDefault:"120.0"`
	SubsMaxResults              int     `env:"SUBS_MAX_RESULTS" envDefault:"2000"`

	// --- Scanner: скан портов (nmap) ---
	PortscanEnabled        bool    `env:"PORTSCAN_ENABLED" envDefault:"true"`
	PortscanNmapBin        string  `env:"PORTSCAN_NMAP_BIN" envDefault:"nmap"`
	PortscanTopPorts       int     `env:"PORTSCAN_TOP_PORTS" envDefault:"1000"`
	PortscanTimeoutSeconds float64 `env:"PORTSCAN_TIMEOUT_SECONDS" envDefault:"300.0"`
	PortscanMaxTargets     int     `env:"PORTSCAN_MAX_TARGETS" envDefault:"64"`
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

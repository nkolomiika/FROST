from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Настройки приложения, загружаемые из переменных окружения."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    database_url: str

    jwt_secret_key: str
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 30

    minio_endpoint: str
    minio_access_key: str
    minio_secret_key: str
    minio_bucket_name: str
    minio_use_ssl: bool = False

    backend_cors_origins: str = "https://localhost:3000,https://127.0.0.1:3000"
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    debug: bool = False

    cookie_secure: bool = True
    cookie_samesite: str = "strict"
    csrf_allowed_origins: str = "https://localhost:3000,https://127.0.0.1:3000"

    initial_admin_username: str = "admin"
    initial_admin_email: str = "admin@example.com"
    initial_admin_password: str = "admin"

    rabbitmq_url: str = "amqp://guest:guest@rabbitmq/"
    mail_queue_name: str = "pcf.mail"
    mail_enabled: bool = True
    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = False
    smtp_use_ssl: bool = False
    smtp_timeout_seconds: float = 20.0
    smtp_from_email: str = "noreply@example.com"
    smtp_from_name: str = "PCF"

    # "password" — обычный SMTP AUTH (mailpit, App Password и т.п.).
    # "xoauth2"  — отправка от лица Google-аккаунта через OAuth2 (см. поля ниже).
    smtp_auth_method: str = "password"
    google_oauth_client_id: str = ""
    google_oauth_client_secret: str = ""
    google_oauth_refresh_token: str = ""
    google_oauth_token_uri: str = "https://oauth2.googleapis.com/token"
    mail_preview_url: str | None = "http://localhost:8025"
    mail_max_attempts: int = 5

    # База для ссылки активации в письме-приглашении (фронтенд): {app_base_url}/activate?token=...
    app_base_url: str = "https://localhost:3000"
    # Срок жизни приглашения (по умолчанию 7 суток).
    invite_token_expire_hours: int = 168
    # Ссылка сброса пароля живёт заметно меньше приглашения: она даёт прямой
    # доступ к существующему аккаунту, поэтому окно атаки держим узким.
    password_reset_expire_hours: int = 2
    # Ссылка возврата деактивированного пользователя: клик по ней разблокирует
    # аккаунт и сразу даёт сессию, поэтому окно тоже держим коротким (сутки).
    reactivation_expire_hours: int = 24

    # --- Jira: единая интеграция на уровне деплоя (не настраивается через веб) ---
    jira_base_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    jira_default_issue_type: str = "Task"
    # Все задачи создаются в этом Jira-проекте (напр. "SEC").
    jira_default_project_key: str = ""
    jira_enabled: bool = True
    # Дата начала = сегодня, срок выполнения = сегодня + jira_due_in_days.
    # ID поля «Дата начала» специфичен для сайта (кастомное поле); пусто = не проставлять.
    jira_start_date_field: str = "customfield_10015"
    jira_due_in_days: int = 14

    # --- Recon farm: серверный пробив вставленных списков хостов и IP ---
    # Максимум различных хостов на один импорт (защита от network-amplification).
    farm_max_targets: int = 256
    # Максимум явных портов на один хост (лишние отбрасываются с пометкой).
    farm_max_ports_per_host: int = 32
    # Таймаут одного HTTP-пробива; истёк — считаем порт не ответившим.
    farm_probe_timeout_seconds: float = 8.0
    # Ограничение одновременных пробивов (semaphore + пул httpx-соединений).
    farm_max_concurrency: int = 20
    # Максимальный размер вставленного текста (и max_length схемы запроса), байт.
    farm_max_raw_bytes: int = 262144
    # Разрешать ли пробив приватных/внутренних IP. По умолчанию НЕТ: ферма ходит
    # только во внешнюю сеть (SSRF-guard). Включать осознанно на изолированном стенде.
    farm_allow_private_targets: bool = False
    # Обратный резолв (PTR + forward-confirm) при импорте IP. Выключать на
    # изолированном стенде без DNS, чтобы не ждать таймаутов на каждом адресе.
    farm_reverse_dns_enabled: bool = True
    # Импорт IP: подтверждённые PTR-имена адреса прогонять через ферму хостов —
    # искать их веб-порты и сервисы и заводить полноценным Host(origin=host).
    farm_ip_resolve_hosts_enabled: bool = True
    # Импорт хостов: адреса, в которые резолвятся домены, отдельно пробивать
    # фермой IP (запрос к голому IP, без Host-заголовка) и заводить строкой
    # origin='ip'. Ответ на IP и на домен у vhost различается, поэтому статусы
    # портов домена и его адреса собираются раздельно — зеркало
    # farm_ip_resolve_hosts_enabled в обратную сторону.
    farm_host_resolve_ips_enabled: bool = True
    # Таймаут одного PTR/forward-запроса: у socket.gethostbyaddr своего таймаута
    # нет, а setdefaulttimeout глобален на процесс — оборачиваем в wait_for.
    farm_reverse_dns_timeout_seconds: float = 3.0
    # Прогонять задачи фермы через RabbitMQ и отдельный контейнер recon-worker.
    # false — старое поведение: BackgroundTasks в процессе API (dev и тесты).
    recon_worker_enabled: bool = True
    recon_queue_name: str = "recon"
    # Сколько раз воркер пробует задачу, прежде чем оставить её failed.
    recon_max_attempts: int = 3
    # Джоба, застрявшая в queued/running дольше этого (воркер умер между
    # публикацией и записью статуса, или посреди пробива), возвращается в pending
    # и переигрывается. Порог с запасом больше реального времени пробива, чтобы
    # не реклеймить живую задачу параллельно исполняющемуся воркеру.
    recon_stale_job_seconds: int = 1800
    # Кап на число построчных элементов (hosts/ips/files/errors), сохраняемых в
    # job.result JSON. Счётчики (hosts_created, ports_created, …) остаются точными —
    # обрезается только детальный «эхо-список». Развязывает размер result-блоба от
    # farm_max_targets: на масштабе тысяч целей джоб-строка не разрастается.
    recon_result_max_items: int = 200
    # --- Ферма JS: поиск .js на домене, скачивание, греп секретов и путей ---
    js_farm_max_files_per_host: int = 50
    # Кап на размер одного .js (бандлы бывают большими, но читаем в память).
    js_farm_max_file_bytes: int = 5_000_000
    js_farm_download_timeout_seconds: float = 15.0
    js_farm_max_concurrency: int = 10
    # Общий кап файлов на задачу — защита от разрастания.
    js_farm_max_total_files: int = 500
    # --- Определение технологий и CDN веб-порта при пробиве ---
    # Выключить, если инструменты не установлены: порты останутся «unknown».
    services_detect_enabled: bool = True
    # Движок: httpx (ProjectDiscovery, по умолчанию — быстрее/точнее) | whatweb.
    services_detect_engine: str = "httpx"
    # httpx-pd — бинарь ProjectDiscovery (не путать с pip-пакетом httpx).
    services_httpx_bin: str = "httpx-pd"
    services_whatweb_bin: str = "whatweb"
    services_detect_timeout_seconds: float = 20.0
    services_max_concurrency: int = 6

    # --- Scanner: раскрытие поддоменов корневого домена ---
    # Источник Certificate Transparency (crt.sh) — HTTP JSON, ключ не нужен.
    subs_crtsh_enabled: bool = True
    subs_crtsh_timeout_seconds: float = 30.0
    # subfinder (ProjectDiscovery) — если бинарь установлен; иначе тихо пропускаем.
    subs_subfinder_enabled: bool = True
    subs_subfinder_bin: str = "subfinder"
    subs_subfinder_timeout_seconds: float = 120.0
    # Кап на число найденных поддоменов, прогоняемых дальше фермой хостов.
    subs_max_results: int = 2000

    # --- Scanner: скан открытых TCP-портов (nmap) ---
    portscan_enabled: bool = True
    portscan_nmap_bin: str = "nmap"
    # Сколько верхних портов сканировать (nmap --top-ports). 0 = все 65535 (медленно).
    portscan_top_ports: int = 1000
    # Таймаут одного запуска nmap (на всю пачку целей), секунд.
    portscan_timeout_seconds: float = 300.0
    # Максимум целей на один скан (nmap запускается одной командой на пачку).
    portscan_max_targets: int = 64

    @property
    def jira_configured(self) -> bool:
        """Заданы ли все обязательные параметры подключения к Jira."""
        return bool(self.jira_base_url and self.jira_email and self.jira_api_token)

    @field_validator("jwt_secret_key")
    @classmethod
    def validate_secret_key(cls, value: str) -> str:
        """Проверяет минимальную длину JWT-секрета."""
        if len(value) < 32:
            raise ValueError("JWT_SECRET_KEY должен содержать минимум 32 символа")
        return value

    @property
    def cors_origins(self) -> list[str]:
        """Возвращает список разрешённых CORS-источников."""
        return [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]

    @property
    def csrf_origins(self) -> list[str]:
        """Возвращает список разрешённых Origin для CSRF-проверки."""
        return [origin.strip() for origin in self.csrf_allowed_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Возвращает кешированный объект настроек."""
    return Settings()

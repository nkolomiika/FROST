# Архитектура STORM (Offensive Security Research & Management)

> Документ описывает АКТУАЛЬНОЕ состояние кода в репозитории. Структура backend — плоская: один `app/services.py`, один `app/schemas.py`, один `app/models.py` (без Repository pattern и без подкаталога `repositories/`).
>
> См. также: [`ARCH_DIAGRAM.md`](./ARCH_DIAGRAM.md) — Mermaid-диаграммы.

---

## 1. Архитектура системы

### Общая схема (Docker Compose)

Развёртывание состоит из следующих сервисов:

- `frontend` — React + Vite (HTTPS, порт 3000), проксирует `/api` и `/ws` на `backend`.
- `backend` — FastAPI (uvicorn, порт 8000): REST API `/api/v1`, машинный API `/api/v2` для AI-агентов, WebSocket `/ws/*`.
- `db` — PostgreSQL: основная БД (async-доступ через asyncpg). Хранит и доменные данные, и audit-журнал.
- `minio` — S3-совместимое хранилище для аватаров пользователей и evidence-файлов уязвимостей.
- `rabbitmq` — брокер сообщений для очереди отправки писем (`pcf.mail`).
- `mail-worker` — отдельный sidecar-процесс, потребляющий `pcf.mail` и отправляющий письма по SMTP.
- `mailpit` (dev) / внешний SMTP (prod) — приём писем.

### Стек

**Backend**
- Python 3.12, FastAPI
- SQLAlchemy 2.x (async, `AsyncSession`) + Alembic
- Pydantic v2 / pydantic-settings
- JWT через `python-jose`, bcrypt через `passlib`
- `python-magic` (детекция MIME), Pillow (обработка изображений)
- `cvss` (вычисление CVSS), `httpx` (HTTP-клиент для Jira)
- `minio` (SDK MinIO)
- `aio-pika` (RabbitMQ), `aiosmtplib` (SMTP в worker)

**Frontend**
- React 18 + TypeScript, сборка через Vite 6
- MUI 6 (`@mui/material`, `@mui/icons-material`)
- React Router 6
- Zustand (state) — `useAuthStore`, `useToastStore`
- `axios` (HTTP-клиент), `react-markdown` (рендер Markdown)
- TipTap 2.x — WYSIWYG/Markdown-редактор (`@tiptap/react`, `@tiptap/starter-kit`, `tiptap-markdown`)
- `js-yaml` — парсинг OpenAPI YAML на клиенте
- Vitest + Testing Library — unit-тесты

---

## 2. Структура backend (фактическая, плоская)

```
backend/
├── app/
│   ├── main.py                    # FastAPI startup, монтирование роутеров, error handlers,
│   │                              # ad-hoc ALTER TABLE миграции для совместимости
│   ├── config.py                  # Pydantic Settings (.env), валидация JWT-секрета (>= 32 симв.)
│   ├── database.py                # async engine + async_sessionmaker, Base
│   ├── dependencies.py            # get_current_user, require_admin, require_project_access,
│   │                              # enforce_csrf, get_agent_token_context, require_agent_scope,
│   │                              # require_agent_project_access
│   ├── enums.py                   # UserRole, ProjectStatus, Severity, VulnerabilityStatus,
│   │                              # AssetType, HostStatus, Protocol, PortState, HttpMethod,
│   │                              # CvssVersion, NotificationType
│   ├── exceptions.py              # PCFError, NotFoundError, UnauthorizedError, ForbiddenError,
│   │                              # ConflictError, ValidationError
│   ├── models.py                  # ВСЕ ORM-модели одним файлом: User, RefreshToken,
│   │                              # AgentApiToken, AgentApiTokenProjectGrant, MailJob,
│   │                              # Project, ProjectFolder, ProjectMember,
│   │                              # JiraInstance, ProjectJiraLink, JiraIssueLink,
│   │                              # ProjectNote, ProjectNoteComment,
│   │                              # Host, HostIpAddress, Port, Service, Endpoint,
│   │                              # Vulnerability, VulnerabilityAsset,
│   │                              # File, Comment, CommentMention,
│   │                              # Notification, AuditLog
│   ├── schemas.py                 # ВСЕ Pydantic-схемы (request/response) одним файлом
│   ├── services.py                # ВСЕ сервисные классы одним файлом:
│   │                              #   AuditService, AgentTokenService, JiraIntegrationService,
│   │                              #   AuthService, UserService, ProjectService, AssetService,
│   │                              #   VulnerabilityService, FileService, CommentService,
│   │                              #   ProjectNoteService, NotificationService,
│   │                              #   ImportService, ReportService
│   ├── security.py                # bcrypt (hash_password / verify_password), JWT encode/decode,
│   │                              # hash_refresh_token (SHA-256), hash_agent_token (SHA-256)
│   ├── pagination.py              # PageParams, to_paginated_response
│   ├── ws_manager.py              # WebSocket connection manager:
│   │                              #   broadcast по project_id, notify_user по user_id,
│   │                              #   projects-index общий канал
│   ├── messaging.py               # publish_mail_job в RabbitMQ
│   ├── mail.py                    # build_temporary_password_email (рендер шаблона)
│   ├── routers/
│   │   ├── auth.py                # /auth — login, refresh (rotation), logout,
│   │   ├── users.py               # /users — CRUD, /me, /me/profile, /me/avatar,
│   │   │                          # password reset (admin)
│   │   ├── projects.py            # /projects — CRUD проектов и папок (folders + move),
│   │   │                          # members
│   │   ├── project_notes.py       # /projects/{id}/notes — Confluence-like заметки
│   │   │                          # (иерархия parent/sort_order) и комментарии к ним
│   │   ├── assets.py              # /projects/{id}/hosts/* — hosts, ports, services,
│   │   │                          # endpoints (HostIpAddress управляется через Host)
│   │   ├── vulnerabilities.py     # /projects/{id}/vulnerabilities — CRUD, status,
│   │   │                          # workflow_steps, привязка к assets
│   │   ├── files.py               # загрузка/скачивание/удаление evidence-файлов
│   │   ├── comments.py            # комментарии к уязвимостям + @mention
│   │   ├── notifications.py       # список, unread-count, mark-read, read-all
│   │   ├── import_.py             # импорт PCF JSON, импорт/экспорт OpenAPI для хоста
│   │   ├── jira.py                # /jira/config (admin), /projects/{id}/jira-link,
│   │   │                          # экспорт уязвимости в Jira issue
│   │   ├── reports.py             # генерация Word-отчётов: ПП и СЗИ
│   │   ├── audit_logs.py          # чтение audit-логов из PostgreSQL (full-text + фильтры)
│   │   ├── agent_tokens.py        # /agent-tokens — управление Bearer-токенами для AI агентов
│   │   ├── v2_agent.py            # публичный /api/v2 для AI агентов (Bearer auth)
│   │   └── websocket.py           # /ws/notifications, /ws/projects/{id}, /ws/projects-index
│   ├── reports/
│   │   ├── __init__.py            # build_pp(...), build_szi(...)
│   │   └── word_builder.py        # генерация .docx через python-docx
│   ├── storage/
│   │   └── minio_client.py        # MinioStorage: ensure_bucket, upload/download/delete bytes
│   └── worker/
│       └── mail_worker.py         # RabbitMQ consumer: разбирает MailJob, шлёт по SMTP,
│                                  # ретраи (mail_max_attempts), relay_pending_jobs
├── migrations/                    # Alembic
│   ├── env.py
│   └── versions/
│       ├── 20260415_0001_initial_schema.py
│       ├── 20260416_0002_drop_host_os_column.py
│       ├── 20260420_0003_create_mail_jobs.py
│       ├── 20260430_0004_create_project_notes.py
│       ├── 20260512_0005_create_host_ip_addresses.py
│       ├── 20260513_0006_create_agent_api_tokens.py
│       └── 20260513_0007_create_jira_integration.py
├── scripts/
│   └── reset_and_seed.py          # сброс и заполнение БД для dev-окружения
├── tests/                         # pytest + pytest-asyncio (94+ тестов)
├── Dockerfile
├── pytest.ini
├── alembic.ini
└── requirements.txt
```

---

## 3. Структура frontend (фактическая)

```
frontend/src/
├── main.tsx                       # точка входа React (createRoot)
├── App.tsx                        # Router, PrivateLayout, AppBar с notifications,
│                                  # WebSocket /ws/notifications
├── api.ts                         # axios-клиент (withCredentials), все API-функции
├── store.ts                       # zustand: useAuthStore, useToastStore
├── types.ts                       # TypeScript-типы (DTO моделей)
├── cvss.ts                        # вычисление CVSS (v3.x, v4.0)
├── projectStatus.ts               # лейблы и цвета статусов проектов
├── requestFormat.ts               # форматирование HTTP-запросов для отображения
├── useErrorToast.ts               # хук показа ошибок через useToastStore
├── markdownUrlTransform.ts        # urlTransform для react-markdown
│                                  #   (whitelist: http/https/mailto + data:image/* base64)
├── setupTests.ts                  # настройка vitest + jest-dom
├── components/
│   ├── MarkdownEditor.tsx         # WYSIWYG/Markdown-редактор на TipTap
│   ├── MarkdownImage.tsx          # рендер картинок (включая data:)
│   ├── MarkdownOutlinedReadonlyField.tsx   # readonly markdown с outlined-видом
│   ├── ProjectTreeNav.tsx         # дерево навигации проекта (hosts/notes/vulns)
│   ├── ProjectHostsTreePopover.tsx
│   ├── ProjectNotesSection.tsx    # секция заметок проекта
│   ├── ProjectNotesTreePopover.tsx
│   └── VulnerabilityStagesEditor.tsx   # редактор workflow_steps
├── pages/
│   ├── LoginPage.tsx
│   ├── ForceChangePasswordPage.tsx
│   ├── ProjectsPage.tsx           # список проектов с папками (drag&drop)
│   ├── ProjectDetailPage.tsx
│   ├── HostDetailPage.tsx
│   ├── ProfilePage.tsx
│   ├── UsersAdminPage.tsx
│   ├── AuditLogsPage.tsx
│   └── AiAgentIntegrationPage.tsx # управление agent tokens и Jira config (admin)
├── test/
│   └── renderWithProviders.tsx
├── tsconfig*.json
└── vite.config.ts                 # HTTPS dev, proxy /api и /ws на backend:8000,
                                   # vitest (jsdom), exclude **/*.test.js
```

---

## 4. Сервисы и инфраструктура

| Сервис      | Назначение                                                   | Доступ из backend                                          |
|-------------|--------------------------------------------------------------|------------------------------------------------------------|
| PostgreSQL  | основная БД                                                  | `database_url` (asyncpg), `app/database.py`                |
| MinIO       | хранилище файлов (avatars, vulnerability evidence)           | `app/storage/minio_client.py` (`MinioStorage`)             |
| RabbitMQ    | очередь `pcf.mail` для асинхронной отправки писем            | publish — `app/messaging.py`, consume — `app/worker/`      |
| Mailpit/SMTP| отправка писем (dev — Mailpit, prod — внешний SMTP)          | `app/worker/mail_worker.py` (aiosmtplib)                   |
| Jira REST   | (опционально) экспорт уязвимостей в Jira issues              | `JiraIntegrationService` (httpx), backend-only             |

---

## 5. Аутентификация и авторизация

### JWT в HttpOnly Secure cookies

- `access_token` — TTL по умолчанию **30 минут**, `path=/`.
- `refresh_token` — TTL **30 дней**, `path=/api/v1/auth/refresh`.
- Оба cookie: `HttpOnly`, `Secure` (`cookie_secure=true`), `SameSite=strict` (`cookie_samesite`).
- Параметры через `Settings`: `jwt_access_token_expire_minutes`, `jwt_refresh_token_expire_days`, `jwt_secret_key` (минимум 32 символа).

### Refresh с ротацией

- На каждый успешный `/api/v1/auth/refresh` старый refresh отзывается, выдаётся новый (rotation).
- При попытке reuse уже отозванного refresh — отзываются **все** активные refresh-токены пользователя (защита от кражи).
- В БД хранится только `SHA-256` хеш токена (`RefreshToken.token_hash`).

### CSRF

- `enforce_csrf` (`dependencies.py`) проверяет заголовок `Origin` для всех state-changing запросов (`POST/PUT/PATCH/DELETE`).
- Origin должен входить в whitelist `csrf_allowed_origins`.

### Bootstrap admin

- При запуске, если таблица `users` пуста, создаётся пользователь из `initial_admin_username` / `initial_admin_email` / `initial_admin_password`.

### Роли

`UserRole` (аккаунтная): `admin`, `pentester`. `ProjectRole` (проектная, глобальная, задаётся в /members): `lead`, `pentester`.

### Доступ к проектам

- `admin` — доступ ко всем проектам.
- Прочие роли — через `ProjectMember` (явное членство).
- Проверка: `require_project_access` (web) и `require_agent_project_access` (agent token).

### Agent API v2 (Bearer)

- Хранение: `AgentApiToken.token_hash` = SHA-256 от выданного токена; в БД сохраняется `token_prefix` (для удобной идентификации в UI).
- Скоупы (любые комбинации):
  `projects:read`, `projects:write`, `assets:read`, `assets:write`,
  `vulns:read`, `vulns:write`, `notes:read`, `notes:write`.
- Доступ к проектам: либо `all_projects=True`, либо явные записи в `AgentApiTokenProjectGrant`.
- Поля контроля: `expires_at`, `revoked_at`, `last_used_at` (обновляется при каждом запросе).

---

## 6. Безопасность

- **Пароли**: bcrypt (`passlib`), хеш токенов в БД — SHA-256 (`security.hash_refresh_token`, `security.hash_agent_token`).
- **CSRF**: проверка `Origin` на мутирующих методах против `csrf_origins` whitelist.
- **CORS**: `allow_credentials=True`, фиксированный whitelist methods (`GET, POST, PUT, PATCH, DELETE, OPTIONS`) и headers (`Authorization, Content-Type, X-Requested-With, Origin, Accept`).
- **File uploads** (evidence-файлы):
  - Проверка реального MIME через `python-magic` (а не только `Content-Type`).
  - Whitelist разрешённых типов.
  - Sanitization имени файла: `basename` + удаление управляющих символов.
  - Лимит размера: `CHECK size_bytes <= 50 MiB` на уровне БД.
- **Аватары пользователей**: только `image/png|jpeg|webp|gif` (без SVG — антиXSS).
- **SSRF-защита Jira `base_url`**: запрет схем кроме `https`, отказ от `localhost`/loopback/private/link-local IP.
- **Audit log**: единое хранилище — PostgreSQL-таблица `audit_logs` (`AuditService.log()` пишет один раз и сразу коммитит). Чтение через `GET /api/v1/audit-logs` с фильтрами и full-text-поиском по action/entity_type/ip/username/details.
- **Markdown XSS**: `react-markdown` с `urlTransform` whitelist — `http/https/mailto` + только `data:image/...;base64,...` (см. `markdownUrlTransform.ts`).

---

## 7. Real-time (WebSocket)

| Endpoint                          | Назначение                                                         |
|-----------------------------------|--------------------------------------------------------------------|
| `/ws/notifications`               | Личный канал пользователя — push новых in-app уведомлений (mention)|
| `/ws/projects/{project_id}`       | Канал проекта — события CRUD: hosts, ports, services, endpoints,   |
|                                   | vulnerabilities, comments, notes                                    |
| `/ws/projects-index`              | Общий канал списка проектов (обновления при создании/изменении)    |

Аутентификация WS — через `access_token` cookie (JWT). Доступ к каналу проекта — через `ProjectMember` (или admin).

`ws_manager` (`app/ws_manager.py`):
- `connect(project_id, ws)` / `broadcast(project_id, event)` — события проекта.
- `connect_user(user_id, ws)` / `notify_user(user_id, event)` — личные уведомления.
- `connect_projects_index(ws)` / `broadcast_projects_index(event)` — общий список проектов.

---

## 8. Background jobs

### mail_worker (`app/worker/mail_worker.py`)

- Подключается к RabbitMQ (`rabbitmq_url`), потребляет очередь `mail_queue_name` (по умолчанию `pcf.mail`).
- На каждое сообщение находит `MailJob` в БД, рендерит письмо (`app/mail.py`) и отправляет через SMTP (`smtp_host:smtp_port`, опц. STARTTLS/SSL).
- Ретраи: до `mail_max_attempts` попыток; при неудаче статус `MailJob.status = failed`, ошибка пишется в `last_error`.
- `relay_pending_jobs`: периодическая задача, которая перепубликует в очередь зависшие `pending` MailJob'ы (например, если воркер был недоступен в момент publish).

### Ad-hoc DB миграции при старте

`main.py::startup()`:
- Создаёт таблицы (`Base.metadata.create_all`).
- Выполняет идемпотентные `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` для совместимости с уже задеплоенными базами (вместо полноценных Alembic-миграций для добавляемых колонок).
- Расширяет PostgreSQL ENUM'ы (`ADD VALUE IF NOT EXISTS 'developer'`, `'handover_to_development'`, `'vulnerability_recheck'`).
- Выполняет идемпотентную трансформацию `vulnerabilities.workflow_steps` — удаление поля `title` из элементов JSON-массива.
- `MinioStorage().ensure_bucket()` — создание бакета MinIO при необходимости.
- `UserService.bootstrap_admin()` — стартовый администратор.

---

## 9. Особенности реализации

- **Плоская структура**: один `models.py`, один `schemas.py`, один `services.py`. Repository pattern не используется — сервисы работают напрямую с `AsyncSession`.
- **Пагинация**: offset-based через `PageParams(page, size)` и `to_paginated_response()`. Списочные endpoint'ы возвращают `{ items, total, page, size, pages }`.
- **CVSS**: расчёт и валидация — на стороне backend (`cvss`) и frontend (`@rohit_coder/cvss` + `cvss.ts`); поддержка v2/v3.x/v4.0.
- **Markdown-редактор**: TipTap с `tiptap-markdown` (round-trip Markdown ↔ ProseMirror), поддержка изображений в `data:` URL.
- **Hosts с несколькими IP**: модель `Host` хранит «основной» IP (`Host.ip_address`) для обратной совместимости + полная таблица `HostIpAddress` (с флагом `is_primary`).
- **Project notes**: иерархическое дерево (`parent_id`, `sort_order`), уникальность `(project_id, parent_id, title)`, отдельные комментарии (`ProjectNoteComment`).
- **Jira integration**: backend-only, выполняется синхронно в HTTP-запросе (без отдельной очереди и jira-worker). Глобальная конфигурация (`JiraInstance`) + per-project link (`ProjectJiraLink`) + per-vulnerability link (`JiraIssueLink`).
- **Frontend state**: zustand вместо Redux; для уведомлений и list-обновлений — WebSocket вместо polling.

---

## 10. API endpoint summary (краткий)

### REST `/api/v1`

| Группа                                          | Описание                                                       |
|-------------------------------------------------|----------------------------------------------------------------|
| `/api/v1/auth/*`                                | login, refresh (rotation), logout                              |
| `/api/v1/users/*`                               | CRUD пользователей, `/me`, `/me/profile`, `/me/avatar`,        |
|                                                 | сброс пароля админом (`PATCH /users/{id}/password`)            |
| `/api/v1/projects/*`                            | CRUD проектов, `/projects/folders` (CRUD папок + move),        |
|                                                 | `/projects/{id}/members`                                       |
| `/api/v1/projects/{id}/notes/*`                 | заметки (иерархия + reorder + move) и комментарии к ним        |
| `/api/v1/projects/{id}/hosts/*`                 | hosts, ports, services, endpoints                              |
| `/api/v1/projects/{id}/vulnerabilities/*`       | CRUD, status, workflow steps, assets-привязки                  |
| `/api/v1/projects/{id}/vulnerabilities/{vid}/files`    | загрузка/скачивание/удаление evidence-файлов            |
| `/api/v1/projects/{id}/vulnerabilities/{vid}/comments` | комментарии + @mention                                  |
| `/api/v1/projects/{id}/vulnerabilities/{vid}/jira/*`   | export уязвимости в Jira issue, чтение связи             |
| `/api/v1/projects/{id}/jira-link`               | привязка проекта к Jira project key                            |
| `/api/v1/projects/{id}/import`                  | импорт результатов сканеров (PCF JSON)                         |
| `/api/v1/projects/{id}/hosts/{hid}/import-openapi`     | импорт endpoints из OpenAPI                              |
| `/api/v1/projects/{id}/hosts/{hid}/export-openapi`     | экспорт endpoints в OpenAPI                              |
| `/api/v1/projects/{id}/reports/szi`             | генерация Word-отчёта СЗИ                                      |
| `/api/v1/projects/{id}/reports/pp`              | генерация Word-отчёта ПП                                       |
| `/api/v1/notifications/*`                       | список, unread-count, mark-read, read-all                      |
| `/api/v1/audit-logs`                            | чтение audit-логов из PostgreSQL (admin)                       |
| `/api/v1/jira/config`                           | глобальная конфигурация Jira (admin)                           |
| `/api/v1/agent-tokens/*`                        | управление API-токенами агентов (admin)                        |

### Машинный API `/api/v2` (Bearer auth)

Смонтирован как отдельное FastAPI-приложение по префиксу `/api/v2` (со своими `/docs` и `/redoc`).

| Endpoint                                            | Scope             |
|-----------------------------------------------------|-------------------|
| `GET /api/v2/projects`                              | `projects:read`   |
| `GET /api/v2/projects/{id}/hosts`                   | `assets:read`     |
| `GET /api/v2/projects/{id}/notes`                   | `notes:read`      |
| `POST /api/v2/projects/{id}/notes`                  | `notes:write`     |
| `PUT /api/v2/projects/{id}/notes/{note_id}`         | `notes:write`     |
| `GET /api/v2/projects/{id}/vulnerabilities`         | `vulns:read`      |
| `POST /api/v2/projects/{id}/vulnerabilities`        | `vulns:write`     |
| `PUT /api/v2/projects/{id}/vulnerabilities/{vid}`   | `vulns:write`     |

### WebSocket

- `WS /ws/notifications`
- `WS /ws/projects/{project_id}`
- `WS /ws/projects-index`

### Service

- `GET /health` — healthcheck.
- `GET /api/v1/openapi.json` — OpenAPI спецификация основного API.
- `GET /api/v2/openapi.json` — OpenAPI спецификация агент-API.

# Архитектура FROST (Findings, Research, Offensive Security & Testing)

> Документ описывает АКТУАЛЬНОЕ состояние кода в репозитории. Backend переписан на **Go** и организован по гексагональной архитектуре (ports & adapters): доменные bounded-контексты в `internal/app/<context>`, порты-реализации в `internal/adapters/*`, точки входа в `cmd/*`. Единый god-service `services.py` из Python-версии разбит на контексты; Repository pattern теперь используется (порт `Store` над sqlc).
>
> См. также: [`ARCH_DIAGRAMS.md`](./ARCH_DIAGRAMS.md) — Mermaid-диаграммы.

---

## 1. Архитектура системы

### Общая схема (Docker Compose)

Развёртывание состоит из следующих сервисов:

- `frontend` — React + Vite за nginx (HTTPS, порт 3000), проксирует `/api` и `/ws` на `backend`.
- `backend` — Go-бинарь `cmd/api` (порт 8000): REST API `/api/v1`, машинный API `/api/v2` для AI-агентов, WebSocket `/ws/*`. Применяет goose-миграции и создаёт стартового админа при старте.
- `db` — PostgreSQL 16: основная БД (доступ через pgx/pgxpool). Хранит и доменные данные, и audit-журнал.
- `minio` — S3-совместимое хранилище для аватаров пользователей и evidence-файлов уязвимостей.
- `rabbitmq` — брокер сообщений (опциональный путь масштабирования; воркеры работают как DB-поллеры и не требуют RabbitMQ на старте).
- `mail-worker` / `recon-worker` — отдельные Go-бинари (`cmd/mail-worker`, `cmd/recon-worker`), DB-поллеры очередей `mail_jobs` и recon/farm.
- `report-sidecar` — временный Python-sidecar генерации `.docx`-отчётов (единственный остаток Python).
- `mailpit` (dev) / внешний SMTP (prod) — приём писем.

### Стек

**Backend**
- Go 1.26, гексагональная архитектура (модуль `github.com/nkolomiika/frost` в `backend-go/`)
- chi v5 (роутер), pgx v5 + sqlc (типобезопасный SQL), goose (миграции, применяются на старте)
- oapi-codegen — генерация серверного кода и типов из контракта `docs/openapi-v{1,2}.json`
- JWT через `golang-jwt/jwt v5`, bcrypt через `golang.org/x/crypto`, TOTP через `pquerna/otp`
- детекция MIME через `http.DetectContentType` (+ ручной разбор WEBP), обработка изображений через `disintegration/imaging`
- CVSS 4.0 — `internal/adapters/cvss` (референс FIRST.org, портирован и сверен с Python)
- `minio-go/v7` (SDK MinIO), `amqp091-go` (RabbitMQ), `coder/websocket`, логирование через `slog`

**Frontend**
- React 18 + TypeScript, сборка через Vite 6
- Zustand (state) — `useAuthStore`, `useToastStore`
- `axios` (HTTP-клиент), `react-markdown` (рендер Markdown)
- TipTap 2.x — WYSIWYG/Markdown-редактор (`@tiptap/react`, `@tiptap/starter-kit`, `tiptap-markdown`)
- `js-yaml` — парсинг OpenAPI YAML на клиенте
- Vitest + Testing Library — unit-тесты

> Актуальный интерфейс — `frontend/src/frost/` (обычный DOM + `frost.css`, без MUI). Каталог `frontend/src/pages/` — прежний MUI-интерфейс, в приложении не используется.

---

## 2. Структура backend (Go, гексагональная)

```
backend-go/
├── cmd/
│   ├── api/                       # composition root HTTP-сервиса: читает config,
│   │                              # поднимает pgxpool, применяет goose-миграции,
│   │                              # bootstrap стартового админа, монтирует роуты chi
│   ├── mail-worker/               # DB-поллер очереди mail_jobs (рендер + SMTP)
│   └── recon-worker/              # DB-поллер recon/farm job-очереди
├── config/                        # загрузка Settings из env (валидация JWT-секрета >= 32 симв.)
├── db/
│   ├── migrations/                # goose SQL-миграции (00001_baseline.sql и далее)
│   └── queries/                   # *.sql для sqlc (auth, users, projects, inventory,
│                                  #  vulns, recon, js, notifications, audit, agent-tokens)
├── internal/
│   ├── domain/<context>/          # сущности и порты (без внешних зависимостей)
│   ├── apperr/                    # kind ошибки → HTTP-код
│   ├── app/                       # use-cases по bounded-контекстам:
│   │   ├── auth/                  #   login, refresh (rotation), logout, 2FA,
│   │   │                          #   invite/password-reset + validate.go
│   │   ├── users/                 #   CRUD, профиль, аватар, сброс пароля
│   │   ├── projects/              #   проекты, папки, участники, заметки, креды, активность
│   │   ├── inventory/             #   hosts/ips/ports/services/endpoints + OpenAPI import/export
│   │   ├── vulns/                 #   CRUD, status, workflow_steps, assets, CVSS
│   │   ├── notifications/         #   список, unread, mark-read
│   │   ├── recon/                 #   farm + scanner (6 видов задач)
│   │   ├── reports/               #   сбор данных для СЗИ/ПП (генерация — sidecar)
│   │   ├── audit/                 #   запись и чтение audit-логов
│   │   ├── agenttokens/           #   выпуск/отзыв Bearer-токенов /api/v2 + скоупы/гранты
│   │   └── mailer/                #   постановка и доставка mail_jobs
│   ├── adapters/
│   │   ├── http/                  # chi-хендлеры (*_handlers.go), DTO из oapi-codegen,
│   │   │                          #   middleware: auth, csrf, requireAdmin,
│   │   │                          #   requireProjectAccessFor; cookies, pagination, apperr
│   │   │   ├── apiv1/             #   сгенерённый сервер/типы для /api/v1 (chi-server)
│   │   │   └── apiv2/             #   сгенерённый сервер/типы для /api/v2 (strict JSON)
│   │   ├── postgres/
│   │   │   ├── sqlc/              #   сгенерённые модели + Querier (из db/queries)
│   │   │   ├── <context>repo/     #   реализация порта Store над sqlc+pgxpool, tx для compound ops
│   │   │   └── pgconv/            #   конвертеры pgtype ↔ domain
│   │   ├── security/             # bcrypt, SHA-256 токены, JWT, Fernet-совместимый шифр, TOTP
│   │   ├── cvss/                 # CVSS 4.0 (референс FIRST.org)
│   │   ├── storage/             # MinIO (Minio + Stub)
│   │   ├── recon/               # parse/resolve/probe/fingerprint/jsscan + netguard (SSRF-гард)
│   │   ├── mail/               # рендер шаблонов + SMTP/XOAUTH2
│   │   ├── messaging/         # amqp091-go (опциональный fanout)
│   │   ├── ws/               # WebSocket-хаб (push уведомлений/событий)
│   │   └── report/           # сбор .docx через sidecar
│   └── platform/{log,postgres}/   # инфраструктурные помощники
├── Dockerfile
├── Makefile                       # make sqlc / oapi / tools / migrate-up/down / test / lint
├── sqlc.yaml
└── go.mod
```

> Генерация кода: контракт `docs/openapi-v{1,2}.json` + goose-схема → `make oapi` (oapi-codegen) и `make sqlc` (sqlc) собирают серверные типы и типобезопасные запросы. Контракт правится руками, код — пересобирается.

---

## 3. Структура frontend (фактическая)

> Ниже — прежний MUI-интерфейс (`frontend/src/pages/`, `frontend/src/components/`), оставленный в репозитории, но в приложении не используемый. Актуальный интерфейс живёт в `frontend/src/frost/` (обычный DOM + `frost.css`, без MUI). Технологический стек (React 18 + TS + Vite 6 + Zustand + axios + TipTap) общий для обоих.

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
│   └── AiAgentIntegrationPage.tsx # управление agent tokens (admin)
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
| PostgreSQL  | основная БД                                                  | `DATABASE_URL` (pgx/pgxpool), `internal/platform/postgres`  |
| MinIO       | хранилище файлов (avatars, vulnerability evidence)           | `internal/adapters/storage` (minio-go v7)                   |
| RabbitMQ    | опциональный fanout для mail/событий (не нужен на старте)     | `internal/adapters/messaging` (amqp091-go)                  |
| Mailpit/SMTP| отправка писем (dev — Mailpit, prod — внешний SMTP)          | `cmd/mail-worker` + `internal/adapters/mail` (SMTP/XOAUTH2) |

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

- CSRF-middleware (`internal/adapters/http/csrf.go`) проверяет заголовок `Origin` для всех state-changing запросов (`POST/PUT/PATCH/DELETE`).
- Origin должен входить в whitelist `CSRF_ALLOWED_ORIGINS`.

### Bootstrap admin

- При запуске `cmd/api`, если таблица `users` пуста, создаётся пользователь из `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_EMAIL` / `INITIAL_ADMIN_PASSWORD`.

### Роли

`UserRole` (аккаунтная): `admin`, `pentester`. `ProjectRole` (проектная, глобальная, задаётся в /members): `lead`, `pentester`.

### Доступ к проектам

- `admin` — доступ ко всем проектам.
- Прочие роли — через `ProjectMember` (явное членство).
- Проверка: middleware `requireProjectAccessFor(authz)` (web, `project_middleware.go`) и аналогичная проверка грантов для agent-токенов (`/api/v2`).

### Agent API v2 (Bearer)

- Хранение: `AgentApiToken.token_hash` = SHA-256 от выданного токена; в БД сохраняется `token_prefix` (для удобной идентификации в UI).
- Скоупы (любые комбинации):
  `projects:read`, `projects:write`, `assets:read`, `assets:write`,
  `vulns:read`, `vulns:write`, `notes:read`, `notes:write`.
- Доступ к проектам: либо `all_projects=True`, либо явные записи в `AgentApiTokenProjectGrant`.
- Поля контроля: `expires_at`, `revoked_at`, `last_used_at` (обновляется при каждом запросе).

---

## 6. Безопасность

- **Пароли**: bcrypt (`golang.org/x/crypto`), хеш токенов в БД — SHA-256 (`internal/adapters/security`).
- **CSRF**: проверка `Origin` на мутирующих методах против `CSRF_ALLOWED_ORIGINS` whitelist.
- **CORS**: credentials разрешены, фиксированный whitelist methods (`GET, POST, PUT, PATCH, DELETE, OPTIONS`) и headers (`Authorization, Content-Type, X-Requested-With, Origin, Accept`).
- **File uploads** (evidence-файлы):
  - Проверка реального MIME через `http.DetectContentType` (+ ручной разбор `RIFF..WEBP`), а не только `Content-Type`.
  - Whitelist разрешённых типов.
  - Sanitization имени файла: `basename` + удаление управляющих символов; MinIO-ключ = `{uuid4}-{sanitized_name}`.
  - Лимит размера: `CHECK size_bytes <= 50 MiB` на уровне БД.
- **Аватары пользователей**: только `image/png|jpeg|webp|gif` (без SVG — антиXSS).
- **SSRF-защита исходящих запросов** (рекон-ферма, `internal/adapters/recon/netguard`): блок-лист loopback/private/link-local/reserved/multicast IP (включая `169.254.169.254`), повторная DNS-валидация перед connect (защита от DNS-rebinding), редиректы отключены.
- **Секреты интеграций**: шифруются Fernet-совместимо (ключ = `urlsafe_b64(sha256(jwt_secret))`).
- **Audit log**: единое хранилище — PostgreSQL-таблица `audit_logs` (use-case `audit` пишет запись синхронно с операцией). Чтение через `GET /api/v1/audit-logs` с фильтрами и full-text-поиском по action/entity_type/ip/username/details.
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

WebSocket-хаб (`internal/adapters/ws`, на `coder/websocket`):
- подписка на канал проекта и broadcast события по `project_id`;
- личный канал пользователя и push уведомлений по `user_id`;
- общий канал списка проектов (`projects-index`).

---

## 8. Background jobs

Воркеры — отдельные Go-бинари и работают как **DB-поллеры**: таблицы `mail_jobs` и recon/farm job — это durable-очереди. API вставляет строку `pending`, воркер опрашивает её (≤5 с) + reclaim. RabbitMQ на старте не требуется (нужен только как путь масштабирования на несколько инстансов).

### mail-worker (`cmd/mail-worker` + `internal/adapters/mail`)

- Поллит `mail_jobs`; на каждую задачу рендерит письмо и отправляет через SMTP (`SMTP_HOST:SMTP_PORT`, опц. STARTTLS/SSL/XOAUTH2).
- Ретраи: до `MAIL_MAX_ATTEMPTS` попыток; при неудаче статус `failed`, ошибка в `last_error`.
- Зависшие `pending`/`failed` (с остатком попыток) переотправляются при следующем опросе.

### recon-worker (`cmd/recon-worker` + `internal/adapters/recon`)

- Поллит recon/farm job-очередь; выполняет 6 видов задач (parse/resolve/probe/fingerprint/jsscan и т. д.) с SSRF-гардом `netguard`.

### Старт `cmd/api`

- Применяет goose-миграции (`db/migrations`) к БД.
- Создаёт бакет MinIO при необходимости.
- Bootstrap стартового администратора, если таблица `users` пуста.

---

## 9. Особенности реализации

- **Гексагональная структура**: bounded-контексты в `internal/app/<ctx>`, порты и реализации в `internal/adapters/*`. Repository pattern используется — use-case обращается к порту `Store`, реализованному в `postgres/<ctx>repo` над sqlc+pgxpool (compound-операции в транзакции).
- **Пагинация**: offset-based через `page`/`size`-параметры (`internal/adapters/http/pagination.go`). Списочные endpoint'ы возвращают `{ items, total, page, size, pages }`.
- **CVSS**: расчёт и валидация — на стороне backend источник истины (`internal/adapters/cvss`, референс FIRST.org) и frontend (`cvss.ts`); severity выводится из вектора. Поддержка v3.x/v4.0.
- **Markdown-редактор**: TipTap с `tiptap-markdown` (round-trip Markdown ↔ ProseMirror), поддержка изображений в `data:` URL.
- **Hosts с несколькими IP**: модель `Host` хранит «основной» IP (`Host.ip_address`) для обратной совместимости + полная таблица `HostIpAddress` (с флагом `is_primary`).
- **Project notes**: иерархическое дерево (`parent_id`, `sort_order`), уникальность `(project_id, parent_id, title)`, отдельные комментарии (`ProjectNoteComment`).
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
| `/api/v1/projects/{id}/import`                  | импорт результатов сканеров (PCF JSON)                         |
| `/api/v1/projects/{id}/hosts/{hid}/import-openapi`     | импорт endpoints из OpenAPI                              |
| `/api/v1/projects/{id}/hosts/{hid}/export-openapi`     | экспорт endpoints в OpenAPI                              |
| `/api/v1/projects/{id}/reports/szi`             | генерация Word-отчёта СЗИ                                      |
| `/api/v1/projects/{id}/reports/pp`              | генерация Word-отчёта ПП                                       |
| `/api/v1/notifications/*`                       | список, unread-count, mark-read, read-all                      |
| `/api/v1/audit-logs`                            | чтение audit-логов из PostgreSQL (admin)                       |
| `/api/v1/agent-tokens/*`                        | управление API-токенами агентов (admin)                        |

### Машинный API `/api/v2` (Bearer auth)

Смонтирован отдельным роутером по префиксу `/api/v2` (strict-server из `apiv2`, чистый JSON), со своей OpenAPI-спецификацией.

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

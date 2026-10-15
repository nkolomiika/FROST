# CONTEXT_ARCH.md — Контекст проекта FROST

> **Назначение:** короткая ориентация для AI-агента / нового разработчика.
> Подробности — в [ARCH.md](ARCH.md), [DB_SCHEMA.md](DB_SCHEMA.md), [DEV_RULES.md](DEV_RULES.md).

---

## 1. Что это

**FROST** (Findings, Research, Offensive Security & Testing) — внутренняя платформа для управления пентест-проектами. Закрытая система: самостоятельной регистрации нет, аккаунты создаёт администратор.

Основные возможности:
- проекты, папки проектов; аккаунтная роль `admin / pentester`, проектная (глобальная) `lead / pentester`;
- инвентарь (хосты с несколькими IP, порты, сервисы, HTTP endpoints);
- уязвимости с CVSS v3.1/v4.0, workflow_steps, файлами-доказательствами, комментариями с `@mention`;
- in-app уведомления и реалтайм через WebSocket;
- импорт/экспорт PCF-JSON и OpenAPI/Swagger по эндпоинтам;
- Confluence-like заметки проекта;
- Word-отчёты (СЗИ и ПП — у ПП все страницы в landscape);
- audit-журнал (Postgres), AI-агент API `/api/v2` по bearer-токенам;
- асинхронная отправка писем через SMTP (Gmail/корпоративный — настраивается `.env`).

---

## 2. Стек

| Слой | Технология |
|------|-----------|
| Backend | **Go 1.26**, гексагональная архитектура (ports & adapters), модуль `github.com/nkolomiika/frost` в `backend-go/` |
| HTTP | chi v5 (роутер), три бинаря: `cmd/api`, `cmd/mail-worker`, `cmd/recon-worker` |
| БД-доступ | pgx v5 + sqlc (типобезопасный SQL, без ORM) |
| Миграции | goose — применяются на старте `cmd/api` |
| Контракт API | oapi-codegen генерирует серверные интерфейсы и типы из `docs/openapi-v{1,2}.json` (это **рукотворный источник истины**, не экспорт из кода) |
| Auth | JWT (`golang-jwt/jwt v5`), bcrypt (`golang.org/x/crypto`) — HttpOnly cookies, не Bearer; TOTP через `pquerna/otp` |
| Файлы | MinIO (`minio-go/v7`, S3-совместимое) |
| Очередь | RabbitMQ (`amqp091-go`) — опциональный путь масштабирования; воркеры работают как DB-поллеры и не требуют RabbitMQ на старте |
| SMTP | стандартный `net/smtp` + XOAUTH2 (Gmail / корпоративный SMTP / mailpit — конфиг через .env) |
| Отчёты | временный Python-sidecar `report-sidecar` (python-docx) — единственный остаток Python |
| WebSocket | `coder/websocket` |
| Логирование | `slog` |
| MIME/изображения | `http.DetectContentType` (+ ручной разбор WEBP), `disintegration/imaging` |
| Frontend | React 18 + TypeScript, Vite 6, Zustand, axios, TipTap |
| БД | PostgreSQL 16 (единое хранилище доменных данных и audit-журнала) |

> **UI.** Актуальный интерфейс — `frontend/src/frost/` (обычный DOM + `frost.css`, **без MUI**). Старые страницы в `frontend/src/pages/` на MUI в приложении не используются (legacy).

---

## 3. Аутентификация — ВАЖНО

Используются **HttpOnly Secure cookies**, не Bearer Authorization headers.

- `access_token` (JWT, ~30 мин) и `refresh_token` (JWT, ~30 дней) — оба `HttpOnly`, `Secure`, `SameSite=Strict`.
- CSRF: `SameSite=Strict` + проверка заголовка `Origin` на мутирующих методах (middleware в `internal/adapters/http`).
- `refresh_tokens` — SHA-256 хэши; сами токены в БД не хранятся; rotation при каждом `/auth/refresh`.
- При logout / смене пароля все refresh-токены пользователя отзываются (`revoked_at`).
- Промежуточное состояние 2FA-pending — короткое (5 мин) окно между вводом пароля и TOTP.

Токен читается из cookie `access_token` (а не из заголовка `Authorization`). Middleware `requireAuth` достаёт его из запроса, валидирует подпись и кладёт пользователя в контекст; хендлеры получают актора из контекста.

```typescript
axios.defaults.withCredentials = true;  // cookie передаётся автоматически
// НЕ устанавливать axios.defaults.headers.common['Authorization']
```

WebSocket — cookie передаётся браузером автоматически в handshake; параметр `?token=` в URL не используется.

**Исключение:** `/api/v2/*` (machine API для AI-агентов) — там Bearer-токен из заголовка `Authorization`. См. контекст `agenttokens`.

---

## 4. Структура

```
FROST/
├── README.md
├── docs/            # ARCH.md, CONTEXT_ARCH.md, DB_SCHEMA.md, DESIGN.md,
│                    # DEV_RULES.md, TASK.md, TEST_CASES.md, USE_CASES.md, openapi-v{1,2}.json
├── docker-compose.yml, docker-compose.prod.yml
├── .env.example, deploy.sh
├── backend-go/                       # Go-бэкенд (hexagonal)
│   ├── Dockerfile, Makefile, go.mod
│   ├── cmd/
│   │   ├── api/                       # HTTP-сервер: роутинг, старт, goose-миграции, bootstrap админа
│   │   ├── mail-worker/               # DB-поллер очереди mail_jobs → SMTP
│   │   └── recon-worker/              # DB-поллер очереди recon/farm
│   ├── config/                        # загрузка настроек из env
│   ├── db/
│   │   ├── migrations/                # goose-миграции (применяются на старте)
│   │   └── queries/                   # sqlc-запросы (*.sql)
│   └── internal/
│       ├── domain/<context>           # сущности и порты (без внешних зависимостей)
│       ├── app/<context>              # use-cases: auth, users, projects, inventory,
│       │                              # vulns, notifications, recon, reports, audit, agenttokens
│       ├── adapters/
│       │   ├── http/                  # хендлеры из oapi-codegen, middleware, cookies, csrf
│       │   ├── postgres/<ctx>repo     # реализации Store-портов (sqlc + pgxpool, tx)
│       │   ├── postgres/sqlc/         # сгенерированный sqlc-код
│       │   ├── storage/               # MinIO
│       │   ├── mail/                  # рендер писем + SMTP
│       │   ├── recon/                 # ферма/сканер + netguard (SSRF-защита)
│       │   ├── cvss/                  # расчёт CVSS 4.0
│       │   ├── report/                # клиент report-sidecar
│       │   ├── ws/                    # WebSocket-хаб
│       │   ├── messaging/             # RabbitMQ (опционально)
│       │   └── security/              # JWT, bcrypt, TOTP, Fernet-совместимое шифрование
│       └── platform/{log,postgres}    # инфраструктурные помощники
├── report-sidecar/                    # временный Python-сервис генерации .docx
└── frontend/
    ├── package.json, vite.config.ts
    └── src/
        ├── api.ts                     # axios instance с interceptors + все API-функции
        ├── store.ts                   # zustand stores (useAuthStore, useToastStore)
        ├── frost/                     # АКТУАЛЬНЫЙ UI (DOM + frost.css): FrostApp, редактор заметок, ...
        └── pages/                     # прежний MUI-интерфейс (не используется)
```

---

## 5. Docker Compose сервисы

```yaml
backend         # Go cmd/api :8000 (REST /api/v1 + /api/v2 + WebSocket)
mail-worker     # Go cmd/mail-worker — DB-поллер mail_jobs → SMTP
recon-worker    # Go cmd/recon-worker — DB-поллер recon/farm
report-sidecar  # временный Python-сервис генерации .docx
frontend        # React/Vite за nginx (TLS) :3000
db              # PostgreSQL 16 :5433→5432
minio           # MinIO :9000 (S3) + :9001 (Console)
rabbitmq        # :15672 management + :5672 amqp (опционально)
mailpit         # dev SMTP catcher :1025 + :8025 web
```

Volumes: `pgdata`, `miniodata`.

Audit-журнал пишется напрямую в PostgreSQL (отдельного хранилища нет).

---

## 6. Доменная модель (PostgreSQL)

| Таблица | Назначение |
|---------|-----------|
| `users` | admin / pentester (+ проектная lead / pentester) |
| `refresh_tokens` | SHA-256 хэши refresh-JWT |
| `agent_api_tokens` + `agent_api_token_project_grants` | Bearer-токены для `/api/v2`, скоупы и список проектов |
| `mail_jobs` | outbox-задания на отправку писем |
| `project_folders`, `projects`, `project_members` | проекты и оргструктура |
| `hosts`, `host_ip_addresses`, `ports`, `services`, `endpoints` | инвентарь |
| `vulnerabilities`, `vulnerability_assets` | уязвимости и привязки к активам |
| `files` | метаданные evidence (контент в MinIO, лимит 50 МБ) |
| `comments`, `comment_mentions` | комментарии и `@mention` |
| `project_notes`, `project_note_comments` | Confluence-like заметки и обсуждения |
| `notifications` | in-app уведомления |
| `audit_logs` | единый журнал действий |

Доменные enums реализованы как **PostgreSQL enum-типы**. В БД и Go-слое хранятся имена членов в верхнем регистре (`ADMIN`, `V31`, …); наружу в API отдаются значения в нижнем регистре (`admin`, `3.1`, …). Исключение — `http_method`: в верхнем регистре с обеих сторон.

| Enum | Значения API |
|------|---------|
| `UserRole` | `admin`, `pentester` |
| `ProjectRole` | `lead`, `pentester` |
| `ProjectStatus` | `active`, `handover_to_development`, `vulnerability_recheck`, `completed`, `archived` |
| `HostStatus` | `up`, `down`, `unknown` |
| `Protocol` | `tcp`, `udp` |
| `PortState` | `open`, `closed`, `filtered` |
| `HttpMethod` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`, `QUERY` |
| `Severity` | `critical`, `high`, `medium`, `low`, `info` |
| `CvssVersion` | `3.1`, `4.0` |
| `VulnerabilityStatus` | `open`, `in_progress`, `fixed`, `wont_fix`, `accepted_risk` |
| `AssetType` | `host`, `port`, `service`, `endpoint` |
| `NotificationType` | `mention`, добавление в проект, смена статуса находки, смена статуса проекта |

---

## 7. API

- Префикс: `/api/v1/` (cookie-auth) и `/api/v2/` (Bearer-auth для AI-агентов).
- Пагинация: offset `?page=1&size=20` → `{ items, total, page, size, pages }`.
- Формат ошибок: `{ "detail": "..." }`. Коды: 400/401/403/404/409/422.
- Контракт зафиксирован в `docs/openapi-v{1,2}.json`; Go-хендлеры генерируются из него через oapi-codegen (`make oapi`).
- Комментарии в коде — на **русском**.

Основные ресурсы `/api/v1/`:

| Ресурс | Путь |
|--------|------|
| Auth | `/auth/{login, refresh, logout, me}` |
| Users | `/users/...` (admin) |
| Projects + folders | `/projects/...` |
| Project notes | `/projects/{id}/notes/...` (+ comments) |
| Hosts/ports/services/endpoints | `/projects/{id}/hosts/...` |
| Vulnerabilities | `/projects/{id}/vulnerabilities/...` |
| Files | `/vulnerabilities/{id}/files/...` |
| Comments | `/vulnerabilities/{id}/comments/...` |
| Notifications | `/notifications/...` |
| Import / Export OpenAPI | `/projects/{id}/import/...`, `/hosts/{id}/(import|export)-openapi` |
| Reports | `/projects/{id}/reports/(szi|pp)` |
| Agent tokens | `/agent-tokens/...` (admin) |
| Audit logs | `/audit-logs` (admin) — фильтры + full-text по action/entity_type/ip/username/details |
| WebSocket | `/ws/notifications`, `/ws/projects/{id}`, `/ws/projects-index` |

---

## 8. Архитектурные паттерны

### Backend
- **Hexagonal (ports & adapters)**: HTTP-хендлер → use-case (`internal/app/<ctx>`) → порт `Store` → репозиторий (`internal/adapters/postgres/<ctx>repo`). Доменный слой не знает о внешних библиотеках.
- **Bounded contexts** вместо одного god-service: auth, users, projects (folders/notes/credentials/activity/hidden-ips), inventory (hosts/ips/ports/services/endpoints + OpenAPI import/export), vulns (CVSS 3.1/4.0), notifications, recon (farm+scanner), reports, audit, agenttokens. Каждый контекст — свои use-cases + порты + репозиторий + HTTP-хендлеры.
- **Repository pattern**: порт `Store` реализуется репозиторием поверх sqlc + pgxpool; составные операции выполняются в транзакции (`r.tx(ctx, func(q *sqlc.Queries) ...)`).
- **DI через composition root**: зависимости собираются в `cmd/api` и передаются хендлерам через `Deps`-структуру (не через FastAPI `Depends`).
- **WebSocket hub** (`internal/adapters/ws`): broadcast по `project_id`, notify по `user_id`, общий канал `projects-index`.
- **Outbox + Worker**: письма создаются как `mail_jobs(status=pending)` → `cmd/mail-worker` поллит очередь (≤5 с) + reclaim зависших и отправляет по SMTP. Аналогично recon-ферма: задания в БД → `cmd/recon-worker`. RabbitMQ — опциональный fanout для нескольких инстансов, не нужен на старте.
- **SSRF исходящих запросов**: `internal/adapters/recon/netguard` — блок-лист loopback/private/link-local/multicast/reserved/unspecified + `169.254.169.254`, развёртка IPv4-в-IPv6, повторная DNS-валидация перед запросом (защита от DNS-rebinding), `follow_redirects=false`.

### Frontend
- **Zustand** для глобального state (auth + toasts), без Redux/Context-overkill.
- **Axios interceptors**: автоматический `/auth/refresh` при 401 → retry.
- **WebSocket** вместо polling для уведомлений и обновлений списков.
- **TipTap + tiptap-markdown** для редактирования Markdown.

---

## 9. Правила разработки (DEV_RULES.md — extract)

- Git flow: `main` + `feature/*` + `hotfix/*`. Conventional Commits.
- PR требует ревью.
- **Комментарии в коде — на русском**; на экспортируемых идентификаторах — doc-комментарии Go (начинаются с имени идентификатора).
- Linting: `gofmt`/`goimports` + `golangci-lint` (backend), `eslint` + `tsc` (frontend).
- Кодогенерация: после правки `docs/openapi-v{1,2}.json` → `make oapi`; после правки `db/queries/*.sql` или миграций → `make sqlc`. Сгенерированные файлы руками не трогать.
- **Запрещено**:
  - Хранить токены в `localStorage` / `sessionStorage`.
  - Передавать токен в URL.
  - Вручную ставить `Authorization: Bearer` для `/api/v1/`.
  - Хардкодить секреты — только через `.env` (`config/`).
  - `SELECT *` — в sqlc-запросах перечислять колонки явно.
  - N+1 — делать выборку одним запросом (JOIN / `= ANY($1)`), а не в цикле.

---

## 10. Безопасность

| Угроза | Защита |
|--------|--------|
| XSS | HttpOnly cookies (JS не имеет доступа к токену), urlTransform whitelist для Markdown (`http/https/mailto` + `data:image/...`) |
| CSRF | `SameSite=Strict` + проверка Origin на мутирующих методах (middleware) |
| SQLi | sqlc + pgx — только параметризованные запросы |
| IDOR | middleware проверки доступа к проекту проверяет принадлежность ресурса проекту на каждый запрос (чужой проект — 403) |
| Утечка токена | Токен только в HttpOnly cookie |
| SSRF (рекон-ферма) | URL-валидация + блок-лист приватных IP + повторная DNS-валидация (DNS-rebind защита) + `follow_redirects=false` |
| Утечка секретов интеграций | Хранятся Fernet-совместимо зашифрованными (ключ = urlsafe_b64(sha256(jwt_secret))) |
| Brute-force | (рекомендовано) rate limiting на nginx/reverse proxy |
| Секреты | Только `.env`, загрузка в `config/` |

---

## 11. SMTP / Mail

`internal/adapters/mail` + `cmd/mail-worker` поддерживают любой SMTP по .env-переменным. В `.env.example` описаны три профиля:

1. **mailpit** (dev) — `SMTP_HOST=mailpit`, без TLS, без auth.
2. **Gmail** (тесты) — `smtp.gmail.com:587`, STARTTLS или XOAUTH2, App password (требует 2FA на аккаунте).
3. **corporate** (prod) — корпоративный SMTP, STARTTLS, реальные креды из vault.

Поле `From` кодируется корректно для кириллицы/спец-символов в display name. Для Gmail `SMTP_FROM_EMAIL` должен совпадать с `SMTP_USERNAME`, иначе Gmail rewrite/refuses.

Триггеры писем: создание пользователя с приглашением, сброс пароля админом. API создаёт `mail_jobs`-строку, воркер рендерит тело и отправляет.

---

## 12. Что покрыто тестами

Go-тесты лежат в пакетах рядом с кодом (`*_test.go`, table-driven):
- `internal/adapters/security` — JWT / bcrypt / TOTP / Fernet-шифрование.
- `internal/adapters/cvss` — расчёт CVSS 4.0 (сверен с Python-референсом).
- `internal/app/*` — use-cases контекстов (auth, projects, inventory, vulns, recon, …) с in-memory фейками портов.
- `internal/adapters/http/*_e2e_test.go` — DB-backed e2e (поднимают схему на реальном Postgres).

Запуск:

```bash
cd backend-go && make test        # go test ./... -race

# DB-e2e под env-флагом:
docker run -d --name pg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=frost -p 55432:5432 postgres:16-alpine
FROST_TEST_DATABASE_URL='postgres://postgres:pw@127.0.0.1:55432/frost' go test ./internal/adapters/http/ -run E2E
```

Frontend — Vitest (`npx vitest run`), тесты рядом с компонентами.

---

## 13. Переменные окружения

Полный шаблон — в [.env.example](.env.example). Ключевые группы:

- `DATABASE_URL` — Postgres.
- `JWT_SECRET_KEY` (мин. 32 символа), `JWT_*_EXPIRE_*`.
- `MINIO_*` — endpoint/credentials/bucket.
- `COOKIE_SECURE`, `COOKIE_SAMESITE`, `CSRF_ALLOWED_ORIGINS`, `BACKEND_CORS_ORIGINS`.
- `INITIAL_ADMIN_*` — стартовый админ при первом запуске.
- `RABBITMQ_URL`, `MAIL_QUEUE_NAME`, `MAIL_ENABLED`, `MAIL_MAX_ATTEMPTS`.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_USE_TLS`, `SMTP_USE_SSL`, `SMTP_FROM_EMAIL`, `SMTP_FROM_NAME`, `GOOGLE_OAUTH_*`.
- `MAIL_PREVIEW_URL` (mailpit UI в dev).

# CONTEXT_ARCH.md — Контекст проекта STORM

> **Назначение:** короткая ориентация для AI-агента / нового разработчика.
> Подробности — в [ARCH.md](ARCH.md), [DB_SCHEMA.md](DB_SCHEMA.md), [DEV_RULES.md](DEV_RULES.md).

---

## 1. Что это

**STORM** (Offensive Security Research & Management) — внутренняя платформа SberTech для управления пентест-проектами. Закрытая система: самостоятельной регистрации нет, аккаунты создаёт администратор.

Основные возможности:
- проекты, папки проектов; аккаунтная роль `admin / pentester`, проектная (глобальная) `lead / pentester`;
- инвентарь (хосты с несколькими IP, порты, сервисы, HTTP endpoints);
- уязвимости с CVSS v3.1/v4.0, workflow_steps, файлами-доказательствами, комментариями с `@mention`;
- in-app уведомления и реалтайм через WebSocket;
- импорт/экспорт PCF-JSON и OpenAPI/Swagger по эндпоинтам;
- Confluence-like заметки проекта;
- Word-отчёты (СЗИ и ПП — у ПП все страницы в landscape);
- Jira-интеграция (экспорт уязвимости в issue) — SSRF + DNS-rebind защита, claim-row anti-race;
- audit-журнал (Postgres), AI-агент API `/api/v2` по bearer-токенам;
- асинхронная отправка писем через RabbitMQ + SMTP (Gmail/корпоративный — настраивается `.env`).

---

## 2. Стек

| Слой | Технология |
|------|-----------|
| Backend | Python 3.12, FastAPI 0.115 |
| ASGI | uvicorn 0.32 |
| ORM | SQLAlchemy 2.0 (async, asyncpg) + Alembic |
| Валидация | Pydantic 2 / pydantic-settings |
| Auth | JWT (python-jose), bcrypt (passlib) — HttpOnly cookies, не Bearer |
| Файлы | MinIO 7.2.x (S3-совместимое) |
| Очередь | RabbitMQ + aio-pika |
| SMTP | aiosmtplib (Gmail / sbertech / mailpit — конфиг через .env) |
| Отчёты | python-docx (Word) |
| HTTP-клиент | httpx 0.28 (+ кастомный transport для DNS-rebind protection в Jira) |
| Frontend | React 18 + TypeScript, Vite 6, MUI 6, Zustand, axios, TipTap |
| БД | PostgreSQL 16 (единое хранилище доменных данных и audit-журнала) |

---

## 3. Аутентификация — ВАЖНО

Используются **HttpOnly Secure cookies**, не Bearer Authorization headers.

- `access_token` (JWT, ~30 мин) и `refresh_token` (JWT, ~30 дней) — оба `HttpOnly`, `Secure`, `SameSite=Strict`.
- CSRF: `SameSite=Strict` + проверка заголовка `Origin` через `enforce_csrf` dependency.
- `refresh_tokens` — SHA-256 хэши; сами токены в БД не хранятся; rotation при каждом `/auth/refresh`.
- При logout / смене пароля все refresh-токены пользователя отзываются (`revoked_at`).

```python
async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    token = request.cookies.get("access_token")  # НЕ Authorization
    if not token:
        raise ForbiddenError("Требуется аутентификация")
    ...
```

```typescript
axios.defaults.withCredentials = true;  // cookie передаётся автоматически
// НЕ устанавливать axios.defaults.headers.common['Authorization']
```

WebSocket — cookie передаётся браузером автоматически в handshake; параметр `?token=` в URL не используется.

**Исключение:** `/api/v2/*` (machine API для AI-агентов) — там Bearer-токен из заголовка `Authorization`. См. `AgentTokenService`.

---

## 4. Структура

```
STORM/
├── README.md
├── ARCH.md, CONTEXT_ARCH.md, DB_SCHEMA.md, DESIGN.md,
├── DEV_RULES.md, TASK.md, TEST_CASES.md, USE_CASES.md
├── docker-compose.yml
├── .env.example
├── backend/
│   ├── Dockerfile
│   ├── alembic.ini, migrations/versions/*.py
│   ├── requirements.txt
│   ├── pytest.ini, tests/...
│   ├── scripts/reset_and_seed.py
│   └── app/
│       ├── main.py            # FastAPI app, startup, routers
│       ├── config.py          # Settings (pydantic-settings) + .env
│       ├── database.py        # async engine, SessionLocal, Base
│       ├── models.py          # ORM модели (один файл)
│       ├── schemas.py         # Pydantic request/response (один файл)
│       ├── enums.py
│       ├── dependencies.py    # get_current_user, require_admin, enforce_csrf, require_project_access
│       ├── exceptions.py
│       ├── security.py        # JWT, bcrypt, agent token hash
│       ├── services.py        # Service Layer (один файл — все сервисы)
│       ├── mail.py            # build_temporary_password_email + send_plain_text_email
│       ├── messaging.py       # publish_mail_job в RabbitMQ
│       ├── pagination.py
│       ├── ws_manager.py      # WebSocket ConnectionManager
│       ├── storage/minio_client.py
│       ├── reports/           # word_builder.py: build_pp / build_szi
│       ├── worker/mail_worker.py   # отдельный процесс (sidecar в compose)
│       └── routers/           # 14 роутеров: auth, users, projects, project_notes,
│                              # assets, vulnerabilities, files, comments,
│                              # notifications, import_, jira, reports,
│                              # audit_logs, agent_tokens, v2_agent, websocket
└── frontend/
    ├── package.json, vite.config.ts
    └── src/
        ├── main.tsx, App.tsx
        ├── api.ts             # axios instance с interceptors + все API-функции
        ├── store.ts           # zustand stores (useAuthStore, useToastStore)
        ├── types.ts
        ├── components/        # ProjectTreeNav, VulnerabilityStagesEditor,
        │                      # NotesTreeInline, ProjectNotesSection,
        │                      # MarkdownEditor, ...
        └── pages/             # LoginPage, ProjectsPage, ProjectDetailPage,
                               # HostDetailPage, AuditLogsPage,
                               # AiAgentIntegrationPage, ...
```

---

## 5. Docker Compose сервисы

```yaml
backend       # FastAPI (uvicorn) :8000
mail-worker   # отдельный процесс, потребляет pcf.mail
frontend      # React/Vite :3000
db            # PostgreSQL 16 :5433→5432
minio         # MinIO :9000 (S3) + :9001 (Console)
rabbitmq      # :15672 management + :5672 amqp
mailpit       # dev SMTP catcher :1025 + :8025 web
```

Volumes: `pgdata`, `miniodata`.

ClickHouse удалён из стека — audit_logs пишутся напрямую в PostgreSQL.

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
| `jira_instances`, `project_jira_links`, `jira_issue_links` | Jira-интеграция |
| `audit_logs` | единый журнал действий |

Ключевые enums (`enums.py`):

| Enum | Значения |
|------|---------|
| `UserRole` | `admin`, `pentester` |
| `ProjectRole` | `lead`, `pentester` |
| `ProjectStatus` | `active`, `handover_to_development`, `vulnerability_recheck`, `completed`, `archived` |
| `HostStatus` | `up`, `down`, `unknown` |
| `Protocol` | `tcp`, `udp` |
| `PortState` | `open`, `closed`, `filtered` |
| `HttpMethod` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS` |
| `Severity` | `critical`, `high`, `medium`, `low`, `info` |
| `CvssVersion` | `3.1`, `4.0` |
| `VulnerabilityStatus` | `open`, `in_progress`, `fixed`, `wont_fix`, `accepted_risk` |
| `AssetType` | `host`, `port`, `service`, `endpoint` |
| `NotificationType` | `mention` |

---

## 7. API

- Префикс: `/api/v1/` (cookie-auth) и `/api/v2/` (Bearer-auth для AI-агентов).
- Пагинация: offset `?page=1&size=20` → `{ items, total, page, size, pages }`.
- Формат ошибок: `{ "detail": "..." }`. Коды: 400/401/403/404/409/422.
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
| Jira | `/jira/config`, `/projects/{id}/jira-link`, `/vulnerabilities/{id}/jira-export` |
| Agent tokens | `/agent-tokens/...` (admin) |
| Audit logs | `/audit-logs` (admin) — фильтры + full-text по action/entity_type/ip/username/details |
| WebSocket | `/ws/notifications`, `/ws/projects/{id}`, `/ws/projects-index` |

---

## 8. Архитектурные паттерны

### Backend
- **Layered**: Router → Service → Model. Repository-pattern не используется — сервисы работают с `AsyncSession` напрямую.
- **Service Layer** в одном файле `services.py` (~4000 строк): UserService, ProjectService, AssetService, VulnerabilityService, FileService, CommentService, ProjectNoteService, NotificationService, ImportService, ReportService, AgentTokenService, JiraIntegrationService, AuditService, AuthService.
- **DI**: FastAPI `Depends()` для `AsyncSession` и текущего пользователя.
- **WebSocket ConnectionManager** (`ws_manager.py`): broadcast по `project_id`, `notify_user` по `user_id`, общий канал `projects-index`.
- **Outbox + Worker**: письма создаются как `MailJob(status=pending)` → publish в RabbitMQ → `mail_worker` отправляет по SMTP. Перепубликация зависших pending'ов через `relay_pending_jobs`.
- **Jira SSRF**: `_validate_external_url` (запрет loopback/private/link-local/multicast/reserved/unspecified) + кастомный `_SafeJiraTransport` (повторная DNS-валидация перед каждым запросом) + claim-row pattern против race condition при параллельных export'ах.

### Frontend
- **Zustand** для глобального state (auth + toasts), без Redux/Context-overkill.
- **Axios interceptors**: автоматический `/auth/refresh` при 401 → retry.
- **WebSocket** вместо polling для уведомлений и обновлений списков.
- **TipTap + tiptap-markdown** для редактирования Markdown.

---

## 9. Правила разработки (DEV_RULES.md — extract)

- Git flow: `main` + `feature/*` + `hotfix/*`. Conventional Commits.
- PR требует ревью.
- **Комментарии в коде — на русском**, docstrings обязательны для публичных функций/классов.
- Linting: `ruff` + `mypy` (backend), `eslint` + `tsc` (frontend).
- **Запрещено**:
  - Хранить токены в `localStorage` / `sessionStorage`.
  - Передавать токен в URL.
  - Вручную ставить `Authorization: Bearer` для `/api/v1/`.
  - Хардкодить секреты — только через `.env`.
  - `SELECT *` — использовать явный список колонок.
  - N+1 — `joinedload`/`selectinload`.

---

## 10. Безопасность

| Угроза | Защита |
|--------|--------|
| XSS | HttpOnly cookies (JS не имеет доступа к токену), urlTransform whitelist для Markdown (`http/https/mailto` + `data:image/...`) |
| CSRF | `SameSite=Strict` + проверка Origin (`enforce_csrf`) |
| SQLi | SQLAlchemy ORM, параметризованные запросы |
| IDOR | `require_project_access` проверяет принадлежность ресурса проекту на каждый запрос |
| Утечка токена | Токен только в HttpOnly cookie |
| SSRF (Jira) | URL-валидация + блок-лист приватных IP + `_SafeJiraTransport` (DNS-rebind защита) + `follow_redirects=False` |
| Race condition (Jira export) | UNIQUE `(vulnerability_id)` + claim-row до HTTP-вызова |
| Утечка Jira API token | Хранится Fernet-encrypted (ключ от SHA-256(jwt_secret_key)) |
| Brute-force | (рекомендовано) rate limiting на nginx/reverse proxy |
| Секреты | Только `.env` + `pydantic-settings` |

---

## 11. SMTP / Mail

`mail.py` + `mail_worker.py` поддерживают любой SMTP по .env-переменным. В `.env.example` описаны три профиля:

1. **mailpit** (dev) — `SMTP_HOST=mailpit`, без TLS, без auth.
2. **Gmail** (тесты) — `smtp.gmail.com:587`, STARTTLS, App password (требует 2FA на аккаунте).
3. **sbertech** (prod) — корпоративный SMTP, STARTTLS, реальные креды из vault.

`From` собирается через `email.utils.formataddr` — корректно кодирует кириллицу/спец-символы в display name. Для Gmail `SMTP_FROM_EMAIL` должен совпадать с `SMTP_USERNAME`, иначе Gmail rewrite/refuses.

Триггеры писем: создание пользователя с `send_invite_email=True`, сброс пароля админом.

---

## 12. Что покрыто тестами

`backend/tests/`:
- `test_security.py`, `test_dependencies.py`, `test_pagination.py`, `test_schemas.py`
- `test_asset_service.py`, `test_project_service.py`, `test_project_note_service.py`
- `test_vulnerability_workflow.py`, `test_comment_service.py`, `test_import_service.py`
- `test_user_service_security.py`, `test_auth_cookies.py`
- `test_report_service.py`, `test_word_builder.py`
- `test_additional_validations.py`

Frontend — Vitest, расположен внутри `frontend/src/__tests__` и рядом с компонентами.

---

## 13. Переменные окружения

Полный шаблон — в [.env.example](.env.example). Ключевые группы:

- `DATABASE_URL` — Postgres.
- `JWT_SECRET_KEY` (мин. 32 символа), `JWT_*_EXPIRE_*`.
- `MINIO_*` — endpoint/credentials/bucket.
- `COOKIE_SECURE`, `COOKIE_SAMESITE`, `CSRF_ALLOWED_ORIGINS`, `BACKEND_CORS_ORIGINS`.
- `INITIAL_ADMIN_*` — стартовый админ при первом запуске.
- `RABBITMQ_URL`, `MAIL_QUEUE_NAME`, `MAIL_ENABLED`, `MAIL_MAX_ATTEMPTS`.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_USE_TLS`, `SMTP_USE_SSL`, `SMTP_FROM_EMAIL`, `SMTP_FROM_NAME`.
- `MAIL_PREVIEW_URL` (mailpit UI в dev).

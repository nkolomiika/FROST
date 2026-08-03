# STORM — Offensive Security Research & Management

Внутренняя платформа SberTech для совместной работы команды пентестеров.
Закрытая система — самостоятельной регистрации нет, аккаунты создаёт администратор.

## Возможности

- **Проекты**: папки, сроки, статусы `active / freeze / handover_to_development / vulnerability_recheck / completed / archived`. Карточку проекта (название, описание, сроки, статус) правят админ, лид проекта или его создатель; удаляет — только админ.
- **Роли**: аккаунтная `admin / pentester` и проектная `lead / pentester` — **обе глобальные**, настраиваются только на странице `/members`. `lead` сам по себе доступа к проекту не даёт: он открывает дополнительные возможности (управление составом команды) в тех проектах, где пользователь уже участник.
- **Доступ по участию**: не-админ видит только те проекты, где он участник — вышел из проекта, и проект пропал из списка. Админ видит все проекты, даже те, где он не состоит. При обращении к чужому проекту или закрытому разделу показывается экран «Доступа нет».
- **Инвентарь**: хосты, несколько IP на хост, порты с сервисами, HTTP endpoints (включая метод `QUERY`); импорт OpenAPI/Swagger; экспорт хостов/IP списком, эндпоинтов — списком или как OpenAPI 3.
- **Уязвимости**: CVSS 4.0 с расчётом по спецификации (бэкенд — источник истины, severity выводится из вектора), шаги воспроизведения, статусы `open / in progress / fixed / won't fix / accepted risk`.
- **Активность проекта**: лента событий по проекту, видна всем его участникам (в отличие от админского `/audit-logs`).
- **Заметки**: live-markdown редактор — `### ` + пробел прямо в строке превращается в заголовок; хранятся как Markdown.
- **Уведомления** — ровно четыре повода: упоминание `@username`, добавление в проект, смена статуса своей находки, смена статуса проекта. Инициатора события никогда не уведомляем. Real-time push через WebSocket.
- **Доказательная база**: evidence-файлы в MinIO (до 50 МБ, whitelist MIME).
- **Word-отчёты** (кнопка «Generate report» на странице проекта): «Отчёт для сертификации» (СЗИ, `POST /projects/{id}/reports/szi`) и «Отчёт внутренней приёмки» (ПП, landscape, `POST /projects/{id}/reports/pp`). PDF не поддерживается — в образе нет конвертера.
- **Jira-интеграция**: экспорт уязвимости в issue (SSRF + DNS-rebind защита).
- **Audit-журнал** в PostgreSQL с фильтрами и full-text поиском.
- **Machine API `/v2`** для AI-агентов: bearer-токены, скоупы, white-list проектов.
- **Mail outbox**: RabbitMQ + воркер `aiosmtplib` (Gmail / корпоративный SMTP через `.env`).

## Стек

Backend: Python 3.12, FastAPI, SQLAlchemy 2 async, Alembic, Pydantic 2, JWT (cookie), bcrypt.
Storage: PostgreSQL 16, MinIO, RabbitMQ.
Frontend: React 18 + TypeScript + Vite 6, Zustand, TipTap (редактор заметок), axios.

> Интерфейс STORM (`frontend/src/storm/`) — это то, что видит пользователь: он собран на
> обычном DOM и `storm.css`, без MUI. Страницы в `frontend/src/pages/` — прежний интерфейс
> на MUI, в приложении не используются.

## Быстрый старт

```bash
cp .env.example .env
# при необходимости поправьте SMTP-секцию (mailpit / Gmail / корпоративный)
docker compose up --build
```

- Frontend: `https://localhost` или `https://localhost:3000`
  (перед приложением стоит nginx с самоподписанным сертификатом — браузер один раз спросит подтверждение)
- **HTTP автоматически редиректится на HTTPS**: `http://localhost` → `https://localhost`,
  `http://localhost:3000` → `https://localhost:3000`
- Backend Swagger: `http://localhost:8000/docs` (`/api/v1`), `http://localhost:8000/v2/docs` (агентский `/v2`)
- MinIO console: `http://localhost:9001` (`minioadmin` / `minioadmin`)
- Mailpit (dev SMTP): `http://localhost:8025`
- RabbitMQ management: `http://localhost:15672` (`guest` / `guest`)

## Dev и прод из одного кода

Один и тот же код запускается локально (dev) и на сервере (prod) — **различаются
только переменные окружения**, никаких правок в исходниках. Выбор окружения — через
переменную `ENV_FILE` (по умолчанию `.env`); прод-настройки лежат в `.env.prod`.

| | Dev (локально) | Prod (сервер) |
|---|---|---|
| Файл окружения | `.env` | `.env.prod` |
| Адрес | `https://localhost`, `:3000` | `https://<адрес-сервера>` |
| CORS / CSRF origins | `localhost` | адрес сервера |
| `APP_BASE_URL` (ссылки в письмах) | `https://localhost:3000` | адрес сервера |
| `DEBUG` | `true` | `false` |
| backend | `--reload` | без reload, `restart: unless-stopped` |
| TLS-сертификат (SAN) | `localhost`, `127.0.0.1` | + IP/домен сервера |

**Локальный dev** — как раньше:

```bash
cp .env.example .env
docker compose up -d --build
```

**Прод** (на сервере):

```bash
cp .env.prod.example .env.prod   # заполнить: адрес, секреты, SMTP
./deploy.sh                       # собрать и поднять прод-стек
# ./deploy.sh recreate  — пересоздать после правки .env.prod
# ./deploy.sh logs|ps|down
```

`deploy.sh` под капотом:
`ENV_FILE=.env.prod docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build`
(плюс экспортирует `CERT_IP`/`CERT_HOST` для самоподписанного сертификата nginx).

> **Фаервол на сервере.** Наружу должен смотреть только nginx — порты `80`, `443`
> (и `22` для SSH). Внутренние порты `8000` (backend), `9000/9001` (MinIO),
> `5433` (Postgres), `1025/8025` (mailpit) закройте облачным фаерволом провайдера.
>
> `.env.prod` содержит реальные секреты и в git не коммитится (см. `.gitignore`);
> в репозитории — только шаблон `.env.prod.example`.

## Учётные записи (локальный dev)

Стартовый админ создаётся при первом запуске из `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` в `.env`.
Демо-команду создаёт `backend/scripts/reset_and_seed.py`. Вход — по **username** (не по email).

| Логин | Пароль | Аккаунтная роль | Проектная роль | Email |
|-----------|---------|-----------------|----------------|---------------------|
| `admin` | `admin` | admin | pentester | admin@example.com |
| `alice` | `admin` | pentester | **lead** | alice@example.com |
| `bob` | `admin` | pentester | **lead** | bob@example.com |
| `charlie` | `admin` | pentester | pentester | charlie@example.com |
| `diana` | `admin` | pentester | pentester | diana@example.com |
| `eve` | `admin` | pentester | pentester | eve@example.com |

> ⚠️ Это дефолты **только для локальной разработки**. На любом общем стенде смените пароли
> и `INITIAL_ADMIN_PASSWORD` в `.env`.

### Роли и доступ

- **admin** — видит все проекты (членство не требуется), управляет пользователями, проектами и составом команд.
- **pentester** — видит **только** проекты, в которых он участник; в чужой проект доступа нет (403).
- **lead** — **глобальная** проектная роль, а не «лид конкретного проекта». Лид остаётся обычным
  пользователем (`pentester`) и получает права только в проектах, где он участник.
  Управлять составом команды и карточкой проекта может: **админ, лид-участник или создатель проекта**.

Обе роли меняются только на странице `/members` (доступна админу).

Пересоздать демо-данные (пользователи сохраняются):

```bash
docker compose exec backend python scripts/reset_and_seed.py
```

## Тесты

```bash
docker compose exec backend python -m pytest -q   # бэкенд
cd frontend && npx vitest run                     # фронтенд
```

## Документация

Вся проектная документация собрана в папке [`docs/`](docs/).

| Файл | Содержание |
|------|-----------|
| [docs/CONTEXT_ARCH.md](docs/CONTEXT_ARCH.md) | Короткая ориентация для AI-агента / нового разработчика |
| [docs/ARCH.md](docs/ARCH.md) | Архитектура, сервисы, роутеры, API |
| [docs/ARCH_DIAGRAMS.md](docs/ARCH_DIAGRAMS.md) | Подробные Mermaid-диаграммы по каждому компоненту |
| [docs/DB_SCHEMA.md](docs/DB_SCHEMA.md) | Схема БД (таблицы, ERD, индексы) |
| [docs/DESIGN.md](docs/DESIGN.md) | UI/UX дизайн-документ |
| [docs/DEV_RULES.md](docs/DEV_RULES.md) | Правила разработки (стиль, безопасность, git flow) |
| [docs/USE_CASES.md](docs/USE_CASES.md) | Сценарии использования по ролям |
| [docs/TASK.md](docs/TASK.md) | Чек-лист реализованного и backlog |
| [docs/TEST_CASES.md](docs/TEST_CASES.md) | Тест-кейсы QA |
| [docs/API_PROCESSES.md](docs/API_PROCESSES.md) | Процессы и сценарии работы с API |
| [docs/GOST_34_DOCUMENTATION.md](docs/GOST_34_DOCUMENTATION.md) | Документация по ГОСТ 34 |
| [docs/openapi-v1.json](docs/openapi-v1.json) | Swagger / OpenAPI 3.1 — `/api/v1` (cookie-auth) |
| [docs/openapi-v2.json](docs/openapi-v2.json) | Swagger / OpenAPI 3.1 — `/v2` (Bearer для AI-агентов) |
| [docs/README.md](docs/README.md) | Как пересоздать OpenAPI-файлы |

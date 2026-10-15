# FROST backend (Go)

Backend FROST на **Go 1.26**, гексагональная архитектура (ports & adapters).
Весь backend переписан на Go — Python в системе больше нет, кроме временного
sidecar-сервиса `report-sidecar` (генерация Word-отчётов `.docx`, см. `../docker-compose.yml`).

Модуль — `github.com/nkolomiika/frost`.

## Раскладка (hexagonal)
- `cmd/{api,mail-worker,recon-worker}` — точки входа (composition root).
  - `api` — HTTP-сервер; на старте применяет goose-миграции и создаёт стартового
    администратора при пустой таблице `users`.
  - `mail-worker` — поллер БД по таблице `mail_jobs` (отправка писем через SMTP).
  - `recon-worker` — поллер БД по очереди задач рекон-фермы.
- `internal/domain/<context>` — сущности и порты (без внешних зависимостей).
- `internal/app/<context>` — use-cases по ограниченным контекстам: auth, users, projects,
  inventory, vulns, notifications, recon, reports, audit, agenttokens.
- `internal/adapters/{http,postgres,storage,messaging,ws,recon,mail,security,cvss,report}` —
  реализации портов. Доступ к БД — через репозитории `postgres/<ctx>repo` поверх sqlc+pgxpool
  (составные операции в транзакции).
- `internal/platform/{log,postgres}` — инфраструктурные помощники.
- `db/{migrations,queries}` — goose-миграции и sqlc-запросы.
- `config/` — загрузка настроек из env.

## Стек
chi v5 (роутер), pgx v5 + sqlc (типизированный SQL, без ORM), goose (миграции),
oapi-codegen (генерация Go-интерфейсов и типов из контракта `../docs/openapi-v{1,2}.json`),
golang-jwt v5, bcrypt, pquerna/otp (TOTP), minio-go v7, amqp091-go (RabbitMQ —
опциональный путь масштабирования), coder/websocket, slog. CVSS 4.0 — `internal/adapters/cvss`.

Воркеры — поллеры БД (`mail_jobs` и очередь рекона — долговечные очереди), поэтому
RabbitMQ не требуется для старта API.

## Запуск (dev)
```bash
go run ./cmd/api          # нужен DATABASE_URL и JWT_SECRET_KEY (>=32 симв.)
make test                 # go test ./... -race
make lint                 # golangci-lint
make sqlc                 # перегенерировать код из db/queries
make oapi                 # перегенерировать код из docs/openapi-v{1,2}.json
```

DB-e2e поднимают схему на реальном Postgres и запускаются под env-флагом:
```bash
docker run -d --name pg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=frost -p 55432:5432 postgres:16-alpine
FROST_TEST_DATABASE_URL='postgres://postgres:pw@127.0.0.1:55432/frost' go test ./internal/adapters/http/ -run E2E
```

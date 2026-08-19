# FROST backend (Go)

Go-перепись backend'а (см. план миграции). Сосуществует с Python-бэкендом `../backend/`
до конца миграции (strangler): готовые эндпоинты обслуживает Go, остальное — Python.

## Раскладка (hexagonal)
- `cmd/{api,mail-worker,recon-worker}` — точки входа (composition root).
- `internal/domain/<context>` — сущности и порты (без внешних зависимостей).
- `internal/app/<context>` — use-cases.
- `internal/adapters/{http,postgres,storage,messaging,ws,recon,mail,security}` — реализации портов.
- `internal/platform/{log,postgres}` — инфраструктурные помощники.
- `db/{migrations,queries}` — goose-миграции и sqlc-запросы.
- `config/` — загрузка настроек из env (зеркало `../backend/app/config.py`).

## Запуск (dev)
```bash
go run ./cmd/api          # нужен DATABASE_URL и JWT_SECRET_KEY (>=32 симв.)
make test                 # go test -race
make lint                 # golangci-lint
```

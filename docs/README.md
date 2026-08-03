# docs/ — Сгенерированные артефакты API

## Файлы

| Файл | Что это |
|------|---------|
| `openapi-v1.json` | OpenAPI 3.1 спецификация пользовательского API `/api/v1` (cookie-auth, 62 endpoint) |
| `openapi-v2.json` | OpenAPI 3.1 спецификация machine API `/api/v2` для AI-агентов (bearer-auth, 6 endpoint) |

Оба файла — `application/json`, можно импортировать в Postman / Insomnia / Bruno / Swagger UI / Stoplight и сравнивать diff'ом в PR.

## Как пересоздать

После любого изменения роутеров или Pydantic-схем обновите файлы:

```bash
# вариант 1: через docker-compose (поднимает только backend без БД)
docker compose run --rm backend python -m scripts.export_openapi

# вариант 2: локально, если установлен Python 3.12 и зависимости
cd backend
python -m scripts.export_openapi
```

Скрипт: [`backend/scripts/export_openapi.py`](../backend/scripts/export_openapi.py).

При первом запуске нужно задать обязательные env-переменные
(скрипт использует `pydantic-settings` для валидации конфига). Минимальный набор для
генерации (без реального коннекта к БД/MinIO):

```bash
export DATABASE_URL='postgresql+asyncpg://x:x@localhost:5432/x'
export JWT_SECRET_KEY='dummy_key_for_export_only_min_32_chars'
export MINIO_ENDPOINT='x:9000'
export MINIO_ACCESS_KEY='x'
export MINIO_SECRET_KEY='x'
export MINIO_BUCKET_NAME='x'
```

## Просмотр

- Локальный Swagger UI (когда backend запущен): `http://localhost:8000/docs` и `http://localhost:8000/api/v2/docs`.
- Online viewer для статического JSON: <https://editor.swagger.io> → File → Import URL/file.

## Связанные документы

- [ARCH.md](ARCH.md) — общая архитектура и таблица endpoint'ов.
- [ARCH_DIAGRAMS.md](ARCH_DIAGRAMS.md) — подробные Mermaid-диаграммы по компонентам.
- [USE_CASES.md](USE_CASES.md) — сценарии использования по ролям.

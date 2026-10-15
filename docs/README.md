# docs/ — Сгенерированные артефакты API

## Файлы

| Файл | Что это |
|------|---------|
| `openapi-v1.json` | OpenAPI 3.1 спецификация пользовательского API `/api/v1` (cookie-auth) |
| `openapi-v2.json` | OpenAPI 3.1 спецификация machine API `/api/v2` для AI-агентов (bearer-auth) |

Оба файла — `application/json`, можно импортировать в Postman / Insomnia / Bruno / Swagger UI / Stoplight и сравнивать diff'ом в PR.

## Источник истины и кодогенерация

> **Направление изменилось.** В Go-бэкенде `openapi-v{1,2}.json` — это **рукотворный контракт
> и источник истины**, а не экспорт из кода. Серверные интерфейсы и типы генерируются ИЗ этих
> файлов через [oapi-codegen](https://github.com/oapi-codegen/oapi-codegen), а не наоборот.

Порядок при изменении API:

1. Отредактируйте контракт — `docs/openapi-v1.json` (или `openapi-v2.json`) вручную.
2. Перегенерируйте Go-код:

```bash
cd backend-go
make oapi            # oapi-codegen по apiv1/cfg.yaml и apiv2/cfg.yaml
```

3. Реализуйте/обновите хендлеры под новые сигнатуры, соберите и прогоните тесты:

```bash
make build && make test
```

Сгенерированные файлы (`internal/adapters/http/apiv{1,2}/*.gen.go`) руками не редактируются —
только контракт и реализация хендлеров.

## Просмотр

- Локальный Swagger UI (когда backend запущен): `http://localhost:8000/docs` и `http://localhost:8000/api/v2/docs`.
- Online viewer для статического JSON: <https://editor.swagger.io> → File → Import URL/file.

## Связанные документы

- [ARCH.md](ARCH.md) — общая архитектура и таблица endpoint'ов.
- [ARCH_DIAGRAMS.md](ARCH_DIAGRAMS.md) — подробные Mermaid-диаграммы по компонентам.
- [USE_CASES.md](USE_CASES.md) — сценарии использования по ролям.

.PHONY: build run test lint vet tidy tools sqlc migrate-up migrate-down oapi baseline-check

build:
	go build ./...

run:
	go run ./cmd/api

test:
	go test ./... -race -count=1

vet:
	go vet ./...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run

tidy:
	go mod tidy

# Кодогенерация из SQL (db/queries + db/schema) -> типобезопасные Go-репозитории.
sqlc:
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@latest generate

# Миграции goose (DSN берётся из окружения GOOSE_DBSTRING).
migrate-up:
	go run github.com/pressly/goose/v3/cmd/goose@latest -dir db/migrations postgres "$$GOOSE_DBSTRING" up

migrate-down:
	go run github.com/pressly/goose/v3/cmd/goose@latest -dir db/migrations postgres "$$GOOSE_DBSTRING" down

# Генерация HTTP-слоя из OpenAPI (контракт фронта): v1 (основной) и v2 (агентский).
# Конфиги: internal/adapters/http/apiv{1,2}/cfg.yaml.
oapi:
	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest -config internal/adapters/http/apiv1/cfg.yaml ../docs/openapi-v1.json
	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest -config internal/adapters/http/apiv2/cfg.yaml ../docs/openapi-v2.json

# Установка codegen-бинарей в $GOPATH/bin (нужен доступ к proxy Go-модулей).
tools:
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	go install github.com/pressly/goose/v3/cmd/goose@latest
	go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest

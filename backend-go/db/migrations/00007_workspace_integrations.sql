-- Контекст integrations: workspace-level ключи внешних сервисов (API-токены OSINT).
-- Значения шифруются в приложении (Fernet, тот же вывод ключа из JWT-секрета, что
-- и для project_credentials.password) и лежат как BYTEA — секреты НИКОГДА не
-- возвращаются наружу, эндпоинт отдаёт лишь факт «configured». key_name — стабильный
-- идентификатор сервиса (github_token, hibp, dehashed, intelx, leakcheck, snusbase,
-- proxynova, …). Пустое значение через PUT удаляет строку.

-- +goose Up
CREATE TABLE workspace_integrations (
    key_name        TEXT PRIMARY KEY,
    value_encrypted BYTEA NOT NULL,
    updated_by      INT REFERENCES users(id) ON DELETE SET NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS workspace_integrations;

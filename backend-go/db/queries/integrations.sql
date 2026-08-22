-- Контекст integrations: workspace-level API-ключи (зашифрованы Fernet, BYTEA).
-- Секреты наружу не отдаём — только факт «configured» + updated_at.

-- name: GetIntegration :one
SELECT key_name, value_encrypted, updated_by, updated_at
FROM workspace_integrations
WHERE key_name = $1;

-- name: ListIntegrations :many
SELECT key_name, updated_by, updated_at
FROM workspace_integrations
ORDER BY key_name;

-- name: UpsertIntegration :exec
INSERT INTO workspace_integrations (key_name, value_encrypted, updated_by, updated_at)
VALUES (sqlc.arg('key_name'), sqlc.arg('value_encrypted'), sqlc.narg('updated_by'), now())
ON CONFLICT (key_name) DO UPDATE
SET value_encrypted = EXCLUDED.value_encrypted,
    updated_by = EXCLUDED.updated_by,
    updated_at = now();

-- name: DeleteIntegration :exec
DELETE FROM workspace_integrations WHERE key_name = $1;

-- Контекст recon, ферма JS: js_files/js_secrets. Скан «в памяти» (файлы в БД не
-- хранятся) — тут только находки, метаданные и апсерт по (project_id, url).

-- name: GetJsFileByProjectURL :one
SELECT * FROM js_files WHERE project_id = $1 AND url = $2;

-- name: UpsertJsFile :one
INSERT INTO js_files (project_id, host_id, url, sha256, size_bytes, content_type, status, error, secret_count, endpoint_count, endpoints, fetched_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT ON CONSTRAINT uq_js_file_project_url DO UPDATE SET
    host_id = EXCLUDED.host_id,
    sha256 = EXCLUDED.sha256,
    size_bytes = EXCLUDED.size_bytes,
    content_type = EXCLUDED.content_type,
    status = EXCLUDED.status,
    error = EXCLUDED.error,
    secret_count = EXCLUDED.secret_count,
    endpoint_count = EXCLUDED.endpoint_count,
    endpoints = EXCLUDED.endpoints,
    fetched_at = EXCLUDED.fetched_at,
    updated_at = now()
RETURNING id;

-- name: DeleteJsSecretsForFile :exec
DELETE FROM js_secrets WHERE js_file_id = $1;

-- name: InsertJsSecret :exec
INSERT INTO js_secrets (js_file_id, kind, match_preview, snippet, severity)
VALUES ($1, $2, $3, $4, $5);

-- name: ListJsFilesForProject :many
SELECT * FROM js_files WHERE project_id = $1 ORDER BY secret_count DESC, url;

-- name: ListJsSecretsForFile :many
SELECT * FROM js_secrets WHERE js_file_id = $1 ORDER BY id;

-- name: ListJsFileURLsForProject :many
SELECT url FROM js_files WHERE project_id = $1 ORDER BY url;

-- name: ListJsFileURLsForHost :many
SELECT url FROM js_files WHERE project_id = $1 AND host_id = $2 ORDER BY url;

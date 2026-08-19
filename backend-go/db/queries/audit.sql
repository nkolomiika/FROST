-- Запросы контекста audit. Пишем журнал действий; чтение — в контексте audit позже.

-- name: InsertAuditLog :exec
INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details, ip_address)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListAuditLogs :many
SELECT a.*, u.username AS username
FROM audit_logs a
LEFT JOIN users u ON u.id = a.user_id
WHERE NOT (a.action = 'LOGIN' AND a.details->>'source' = 'refresh')
  AND (sqlc.narg('user_id')::int IS NULL OR a.user_id = sqlc.narg('user_id'))
  AND (sqlc.narg('username')::text IS NULL OR u.username ILIKE '%' || sqlc.narg('username') || '%')
  AND (sqlc.narg('action')::text IS NULL OR a.action ILIKE '%' || sqlc.narg('action') || '%')
  AND (sqlc.narg('entity_type')::text IS NULL OR a.entity_type ILIKE '%' || sqlc.narg('entity_type') || '%')
  AND (sqlc.narg('entity_id')::int IS NULL OR a.entity_id = sqlc.narg('entity_id'))
  AND (sqlc.narg('ip_address')::text IS NULL OR a.ip_address ILIKE '%' || sqlc.narg('ip_address') || '%')
  AND (sqlc.narg('q')::text IS NULL OR (
        a.action ILIKE '%' || sqlc.narg('q') || '%'
     OR a.entity_type ILIKE '%' || sqlc.narg('q') || '%'
     OR a.ip_address ILIKE '%' || sqlc.narg('q') || '%'
     OR u.username ILIKE '%' || sqlc.narg('q') || '%'
     OR CAST(a.details AS text) ILIKE '%' || sqlc.narg('q') || '%'))
  AND (sqlc.narg('created_from')::timestamptz IS NULL OR a.created_at >= sqlc.narg('created_from'))
  AND (sqlc.narg('created_to')::timestamptz IS NULL OR a.created_at <= sqlc.narg('created_to'))
ORDER BY a.created_at DESC
OFFSET sqlc.arg('offset') LIMIT sqlc.arg('lim');

-- name: CountAuditLogs :one
SELECT count(*)
FROM audit_logs a
LEFT JOIN users u ON u.id = a.user_id
WHERE NOT (a.action = 'LOGIN' AND a.details->>'source' = 'refresh')
  AND (sqlc.narg('user_id')::int IS NULL OR a.user_id = sqlc.narg('user_id'))
  AND (sqlc.narg('username')::text IS NULL OR u.username ILIKE '%' || sqlc.narg('username') || '%')
  AND (sqlc.narg('action')::text IS NULL OR a.action ILIKE '%' || sqlc.narg('action') || '%')
  AND (sqlc.narg('entity_type')::text IS NULL OR a.entity_type ILIKE '%' || sqlc.narg('entity_type') || '%')
  AND (sqlc.narg('entity_id')::int IS NULL OR a.entity_id = sqlc.narg('entity_id'))
  AND (sqlc.narg('ip_address')::text IS NULL OR a.ip_address ILIKE '%' || sqlc.narg('ip_address') || '%')
  AND (sqlc.narg('q')::text IS NULL OR (
        a.action ILIKE '%' || sqlc.narg('q') || '%'
     OR a.entity_type ILIKE '%' || sqlc.narg('q') || '%'
     OR a.ip_address ILIKE '%' || sqlc.narg('q') || '%'
     OR u.username ILIKE '%' || sqlc.narg('q') || '%'
     OR CAST(a.details AS text) ILIKE '%' || sqlc.narg('q') || '%'))
  AND (sqlc.narg('created_from')::timestamptz IS NULL OR a.created_at >= sqlc.narg('created_from'))
  AND (sqlc.narg('created_to')::timestamptz IS NULL OR a.created_at <= sqlc.narg('created_to'));

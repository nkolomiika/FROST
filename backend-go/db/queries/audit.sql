-- Запросы контекста audit. Пишем журнал действий; чтение — в контексте audit позже.

-- name: InsertAuditLog :exec
INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details, ip_address)
VALUES ($1, $2, $3, $4, $5, $6);

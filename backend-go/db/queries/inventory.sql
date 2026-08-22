-- Контекст inventory: hosts/ip-addresses/ports/services/endpoints (+ OpenAPI import/export).
-- hidden-ips живут в контексте projects (те же роуты) — здесь их нет.

-- ─────────── hosts ───────────
-- name: InsertHost :one
INSERT INTO hosts (project_id, ip_address, hostname, status, os_type, notes, origin)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;

-- name: GetHost :one
SELECT * FROM hosts WHERE id = $1 AND project_id = $2;

-- name: ListHosts :many
SELECT * FROM hosts
WHERE project_id = sqlc.arg('project_id')
  AND (sqlc.narg('origin')::text IS NULL OR origin = sqlc.narg('origin'))
  AND (sqlc.narg('status')::host_status IS NULL OR status = sqlc.narg('status'))
ORDER BY created_at DESC OFFSET sqlc.arg('offset') LIMIT sqlc.arg('lim');

-- name: CountHosts :one
SELECT count(*) FROM hosts
WHERE project_id = sqlc.arg('project_id')
  AND (sqlc.narg('origin')::text IS NULL OR origin = sqlc.narg('origin'))
  AND (sqlc.narg('status')::host_status IS NULL OR status = sqlc.narg('status'));

-- name: UpdateHost :one
UPDATE hosts SET ip_address = $2, hostname = $3, status = $4, os_type = $5, notes = $6, updated_at = now()
WHERE id = $1 RETURNING *;

-- name: SetHostPrimaryIP :exec
UPDATE hosts SET ip_address = $2, updated_at = now() WHERE id = $1;

-- name: DeleteHost :exec
DELETE FROM hosts WHERE id = $1 AND project_id = $2;

-- name: BulkDeleteHosts :execrows
-- Пакетное удаление хостов проекта по списку id (скоуп проекта обязателен —
-- чужие id просто не попадают под WHERE). Возвращает число реально удалённых.
DELETE FROM hosts
WHERE project_id = sqlc.arg('project_id') AND id = ANY(sqlc.arg('ids')::int[]);

-- ─────────── host_ip_addresses ───────────
-- name: ListHostIPs :many
SELECT * FROM host_ip_addresses WHERE host_id = $1 ORDER BY created_at;

-- name: ListHostIPsForHosts :many
SELECT * FROM host_ip_addresses WHERE host_id = ANY(sqlc.arg('host_ids')::int[]) ORDER BY host_id, created_at;

-- name: GetHostIPForHost :one
SELECT * FROM host_ip_addresses WHERE id = $1 AND host_id = $2;

-- name: InsertHostIP :one
INSERT INTO host_ip_addresses (host_id, ip_address, label, is_primary, is_cloudflare, hostnames)
VALUES ($1, $2, $3, $4, $5, $6) RETURNING *;

-- name: UpdateHostIP :exec
UPDATE host_ip_addresses SET label = $2, is_primary = $3, is_cloudflare = $4, hostnames = $5, updated_at = now()
WHERE id = $1;

-- name: DeleteHostIP :exec
DELETE FROM host_ip_addresses WHERE id = $1;

-- ─────────── ports ───────────
-- name: ListPortsForHost :many
SELECT * FROM ports WHERE host_id = $1 ORDER BY port_number;

-- name: ListPortsForIPs :many
SELECT * FROM ports WHERE ip_address_id = ANY(sqlc.arg('ip_ids')::int[]) ORDER BY ip_address_id, port_number;

-- name: GetPort :one
SELECT * FROM ports WHERE id = $1 AND host_id = $2;

-- name: FindPortDup :one
SELECT * FROM ports
WHERE ip_address_id = sqlc.arg('ip_address_id') AND port_number = sqlc.arg('port_number') AND protocol = sqlc.arg('protocol')
  AND id <> sqlc.arg('exclude_id')
LIMIT 1;

-- name: InsertPort :one
INSERT INTO ports (host_id, ip_address_id, port_number, protocol, state, http_status)
VALUES ($1, $2, $3, $4, $5, $6) RETURNING *;

-- name: UpdatePort :one
UPDATE ports SET ip_address_id = $2, port_number = $3, protocol = $4, state = $5, http_status = $6, updated_at = now()
WHERE id = $1 RETURNING *;

-- name: DeletePort :exec
DELETE FROM ports WHERE id = $1;

-- ─────────── services ───────────
-- name: ListServicesForPort :many
SELECT * FROM services WHERE port_id = $1 ORDER BY created_at DESC;

-- name: ListServicesForPorts :many
SELECT * FROM services WHERE port_id = ANY(sqlc.arg('port_ids')::int[]) ORDER BY port_id, name;

-- name: GetServiceForPort :one
SELECT * FROM services WHERE id = $1 AND port_id = $2;

-- name: FindServiceByName :one
SELECT * FROM services WHERE port_id = $1 AND name = $2 LIMIT 1;

-- name: InsertService :one
INSERT INTO services (port_id, name, version, banner) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: UpdateService :one
UPDATE services SET name = $2, version = $3, banner = $4, updated_at = now() WHERE id = $1 RETURNING *;

-- name: DeleteService :exec
DELETE FROM services WHERE id = $1;

-- ─────────── endpoints ───────────
-- name: ListEndpointsForHost :many
SELECT * FROM endpoints WHERE host_id = $1 ORDER BY created_at DESC;

-- name: ListEndpointsForHostOrdered :many
SELECT * FROM endpoints WHERE host_id = $1 ORDER BY path, method;

-- name: ListEndpointsForHosts :many
SELECT * FROM endpoints WHERE host_id = ANY(sqlc.arg('host_ids')::int[]) ORDER BY host_id, id;

-- name: GetEndpointForHost :one
SELECT * FROM endpoints WHERE id = $1 AND host_id = $2;

-- name: FindEndpointByPathMethod :one
SELECT * FROM endpoints
WHERE host_id = sqlc.arg('host_id') AND path = sqlc.arg('path')
  AND method IS NOT DISTINCT FROM sqlc.narg('method')
  AND id <> sqlc.arg('exclude_id')
LIMIT 1;

-- name: InsertEndpoint :one
INSERT INTO endpoints (host_id, path, method, description, query_params, request_body, request_content_type, request_headers)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *;

-- name: UpdateEndpoint :one
UPDATE endpoints SET path = $2, method = $3, description = $4, query_params = $5,
    request_body = $6, request_content_type = $7, request_headers = $8, updated_at = now()
WHERE id = $1 RETURNING *;

-- name: DeleteEndpoint :exec
DELETE FROM endpoints WHERE id = $1;

-- name: BulkDeleteEndpoints :execrows
-- Пакетное удаление эндпоинтов по списку id. Принадлежность проекту — через
-- host_id ∈ хостам проекта (эндпоинт чужого проекта не попадает под WHERE).
-- Возвращает число реально удалённых.
DELETE FROM endpoints
WHERE id = ANY(sqlc.arg('ids')::int[])
  AND host_id IN (SELECT id FROM hosts WHERE project_id = sqlc.arg('project_id'));

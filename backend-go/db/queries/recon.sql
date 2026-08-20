-- Контекст recon (ферма + scanner): задачи host_farm_jobs как durable-очередь и
-- запросы персиста хостов/адресов/портов сверх inventory.sql. Модель статусов
-- (порт farm/jobs.py + worker/recon_worker.py): pending→queued→running→done|failed.
-- attempts инкрементится при ВЗЯТИИ в работу (ClaimReconJobRunning), не при провале.
-- Каждый Update*Job СБРАСЫВАЕТ updated_at=now() — reclaim застрявших зависит от него.

-- ─────────── host_farm_jobs (очередь) ───────────

-- name: InsertHostFarmJob :one
INSERT INTO host_farm_jobs (project_id, created_by, kind, status, targets_total, raw, skipped_targets, result, finished_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetHostFarmJob :one
SELECT * FROM host_farm_jobs WHERE id = $1;

-- name: GetHostFarmJobForProject :one
SELECT * FROM host_farm_jobs
WHERE id = sqlc.arg('id') AND project_id = sqlc.arg('project_id') AND kind = sqlc.arg('kind');

-- name: ClaimReconJobRunning :one
-- Атомарно берёт задачу в работу (status='running', attempts++) при статусе, не
-- равном running/done (порт guard run_recon_job: повторную доставку не пробиваем).
UPDATE host_farm_jobs
SET status = 'running', attempts = attempts + 1, updated_at = now()
WHERE id = $1 AND status NOT IN ('running', 'done')
RETURNING *;

-- name: SetJobDone :exec
UPDATE host_farm_jobs
SET status = 'done', result = $2, error = NULL, last_error = NULL, finished_at = now(), updated_at = now()
WHERE id = $1;

-- name: SetJobFailed :exec
UPDATE host_farm_jobs
SET status = 'failed', last_error = sqlc.arg('last_error'), error = sqlc.narg('error'),
    finished_at = now(), updated_at = now()
WHERE id = sqlc.arg('id');

-- name: SetJobQueued :exec
UPDATE host_farm_jobs SET status = 'queued', published_at = now(), last_error = NULL, updated_at = now() WHERE id = $1;

-- name: SelectPendingReconJobs :many
SELECT id FROM host_farm_jobs
WHERE status = 'pending' OR (status = 'failed' AND attempts < sqlc.arg('max_attempts'))
ORDER BY created_at ASC
LIMIT sqlc.arg('lim');

-- name: ReclaimStaleReconJobs :execrows
UPDATE host_farm_jobs SET status = 'pending', updated_at = now()
WHERE status IN ('queued', 'running')
  AND updated_at < now() - (sqlc.arg('stale_seconds')::int * interval '1 second')
  AND attempts < sqlc.arg('max_attempts');

-- ─────────── existing-target keys (create_job) ───────────

-- name: SelectExistingHostnames :many
SELECT hostname FROM hosts
WHERE project_id = sqlc.arg('project_id') AND hostname = ANY(sqlc.arg('names')::text[]);

-- name: SelectExistingHostIPLiterals :many
SELECT ip_address FROM hosts
WHERE project_id = sqlc.arg('project_id') AND ip_address = ANY(sqlc.arg('addrs')::text[]);

-- name: SelectExistingOriginIPAddresses :many
SELECT hia.ip_address FROM host_ip_addresses hia
JOIN hosts h ON h.id = hia.host_id
WHERE h.project_id = sqlc.arg('project_id') AND h.origin = 'ip'
  AND hia.ip_address = ANY(sqlc.arg('addrs')::text[]);

-- name: DeleteHiddenIPs :exec
DELETE FROM project_hidden_ips
WHERE project_id = sqlc.arg('project_id') AND ip_address = ANY(sqlc.arg('addrs')::text[]);

-- ─────────── find-or-create / attach хостов (persist) ───────────

-- name: GetHostByHostname :one
SELECT * FROM hosts WHERE project_id = $1 AND hostname = $2 ORDER BY id LIMIT 1;

-- name: GetHostByIPLiteral :one
SELECT * FROM hosts WHERE project_id = $1 AND ip_address = $2 ORDER BY id LIMIT 1;

-- name: GetOriginIPHostByAddress :one
SELECT h.* FROM hosts h
JOIN host_ip_addresses hia ON hia.host_id = h.id
WHERE h.project_id = $1 AND h.origin = 'ip' AND hia.ip_address = $2
ORDER BY h.created_at
LIMIT 1;

-- name: SetHostStatus :exec
UPDATE hosts SET status = $2, updated_at = now() WHERE id = $1;

-- ─────────── host_ip_addresses (ensure_ips) ───────────

-- name: SetHostIPCloudflare :exec
UPDATE host_ip_addresses SET is_cloudflare = $2, updated_at = now() WHERE id = $1;

-- name: SetHostIPHostnames :exec
UPDATE host_ip_addresses SET hostnames = $2, updated_at = now() WHERE id = $1;

-- ─────────── ports (upsert) ───────────

-- name: GetPortByIPNumberProto :one
SELECT * FROM ports WHERE ip_address_id = $1 AND port_number = $2 AND protocol = $3 LIMIT 1;

-- name: SetPortStateHTTP :exec
UPDATE ports SET state = $2, http_status = $3, updated_at = now() WHERE id = $1;

-- name: SetPortStateOpen :exec
UPDATE ports SET state = 'OPEN', updated_at = now() WHERE id = $1;

-- name: DeleteServicesForPort :exec
DELETE FROM services WHERE port_id = $1;

-- ─────────── выбор целей по проекту ───────────

-- name: ListProjectDomainHostnames :many
SELECT hostname FROM hosts
WHERE project_id = $1 AND origin = 'host' AND hostname IS NOT NULL;

-- name: ListProjectAllHostnames :many
SELECT hostname FROM hosts WHERE project_id = $1 AND hostname IS NOT NULL;

-- name: ListProjectOriginIPs :many
SELECT hia.ip_address FROM host_ip_addresses hia
JOIN hosts h ON h.id = hia.host_id
WHERE h.project_id = $1 AND h.origin = 'ip';

-- name: ListProjectScanTargets :many
SELECT hostname, ip_address FROM hosts WHERE project_id = $1;

-- name: ListProjectOriginHostRows :many
SELECT id, hostname FROM hosts
WHERE project_id = $1 AND origin = 'host' AND hostname IS NOT NULL;

-- name: ListProjectHostIDNames :many
SELECT id, hostname FROM hosts WHERE project_id = $1;

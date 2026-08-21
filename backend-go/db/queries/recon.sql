-- Контекст recon (ферма + scanner): задачи host_farm_jobs как durable-очередь и
-- запросы персиста хостов/адресов/портов сверх inventory.sql. Модель статусов
-- (порт farm/jobs.py + worker/recon_worker.py): pending→queued→running→done|failed.
-- attempts инкрементится при ВЗЯТИИ в работу (ClaimReconJobRunning), не при провале.
-- Каждый Update*Job СБРАСЫВАЕТ updated_at=now() — reclaim застрявших зависит от него.

-- ─────────── host_farm_jobs (очередь) ───────────

-- name: InsertHostFarmJob :one
INSERT INTO host_farm_jobs (project_id, created_by, kind, status, targets_total, raw, skipped_targets, result, progress, finished_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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

-- name: SetJobProgress :exec
-- Обновляет JSON-снимок прогресса полного прогона фермы (kind='farm_run') по мере
-- продвижения стадий. Тоже сбрасывает updated_at, чтобы reclaim не забрал живую задачу.
UPDATE host_farm_jobs SET progress = $2, updated_at = now() WHERE id = $1;

-- name: SetJobCancelled :exec
-- Помечает прогон отменённым (НЕ провал): status='cancelled', частичный result,
-- finished_at=now(). Ошибочные поля чистятся — отмена не является ошибкой.
UPDATE host_farm_jobs
SET status = 'cancelled', result = $2, error = NULL, last_error = NULL, finished_at = now(), updated_at = now()
WHERE id = $1;

-- name: RequestFarmCancel :exec
-- Сигнал отмены ВСЕГО прогона: cancel_requested=true. Только для farm_run задачи
-- этого проекта (иначе строка не совпадёт и апдейт — no-op).
UPDATE host_farm_jobs
SET cancel_requested = true, updated_at = now()
WHERE id = sqlc.arg('id') AND project_id = sqlc.arg('project_id') AND kind = 'farm_run';

-- name: RequestFarmCancelAllActive :execrows
-- Сигнал отмены ВСЕХ активных (pending|running) farm_run задач проекта. Возвращает
-- число затронутых строк.
UPDATE host_farm_jobs
SET cancel_requested = true, updated_at = now()
WHERE project_id = sqlc.arg('project_id') AND kind = 'farm_run' AND status IN ('pending', 'running');

-- name: GetFarmCancelStepsForUpdate :one
-- Читает текущий cancel_steps под блокировкой строки (read-modify-write отмены
-- одного шага). Фильтр по проекту и kind — чужую задачу не трогаем.
SELECT cancel_steps FROM host_farm_jobs
WHERE id = sqlc.arg('id') AND project_id = sqlc.arg('project_id') AND kind = 'farm_run'
FOR UPDATE;

-- name: SetFarmCancelSteps :exec
-- Записывает новый массив id шагов к отмене (маршалится в Go после дедупа).
UPDATE host_farm_jobs SET cancel_steps = $2, updated_at = now() WHERE id = $1;

-- name: GetFarmCancelState :one
-- Снимок управляющих колонок отмены для поллера воркера.
SELECT cancel_requested, cancel_steps FROM host_farm_jobs WHERE id = $1;

-- Воркер гоняет ДВЕ независимые дорожки: «обычная» (все kind, кроме farm_run —
-- держит add-hosts/add-ips/port-scan отзывчивыми) и «фермовая» (только farm_run,
-- долгие прогоны). Отсюда — выборка/реклейм с фильтром по kind, чтобы дорожки не
-- мешали друг другу: длинный farm_run не блокирует обычные задачи, а реклейм
-- обычной дорожки НИКОГДА не трогает бегущий farm_run (и наоборот).

-- name: SelectPendingReconJobsExcludingKind :many
-- Pending обычной дорожки: всё, КРОМЕ переданного kind (= 'farm_run').
SELECT id FROM host_farm_jobs
WHERE (status = 'pending' OR (status = 'failed' AND attempts < sqlc.arg('max_attempts')))
  AND kind <> sqlc.arg('kind')
ORDER BY created_at ASC
LIMIT sqlc.arg('lim');

-- name: SelectPendingReconJobsForKind :many
-- Pending фермовой дорожки: только переданный kind (= 'farm_run').
SELECT id FROM host_farm_jobs
WHERE (status = 'pending' OR (status = 'failed' AND attempts < sqlc.arg('max_attempts')))
  AND kind = sqlc.arg('kind')
ORDER BY created_at ASC
LIMIT sqlc.arg('lim');

-- name: ReclaimStaleReconJobsExcludingKind :execrows
-- Реклейм обычной дорожки: НЕ трогает farm_run (его прогон легитимно длинный,
-- иначе его переигрывали бы как «застрявший» → двойной прогон).
UPDATE host_farm_jobs SET status = 'pending', updated_at = now()
WHERE status IN ('queued', 'running')
  AND kind <> sqlc.arg('kind')
  AND updated_at < now() - (sqlc.arg('stale_seconds')::int * interval '1 second')
  AND attempts < sqlc.arg('max_attempts');

-- name: ReclaimStaleReconJobsForKind :execrows
-- Реклейм фермовой дорожки: только farm_run и с БОЛЬШИМ окном stale_seconds
-- (прогон идёт минутами), чтобы живой прогон не считался застрявшим.
UPDATE host_farm_jobs SET status = 'pending', updated_at = now()
WHERE status IN ('queued', 'running')
  AND kind = sqlc.arg('kind')
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

-- ─────────── стейджинг полного прогона фермы (recon_farm_staged_hosts) ───────────
-- Полный прогон (kind='farm_run') НЕ пишет в проект: находки складываются сюда, а
-- пользователь импортирует выбранное вручную. ports — JSONB-массив портов.

-- name: InsertStagedHost :exec
INSERT INTO recon_farm_staged_hosts (project_id, job_id, hostname, ip, alive, source, ports)
VALUES (sqlc.arg('project_id'), sqlc.arg('job_id'), sqlc.arg('hostname'), sqlc.arg('ip'),
        sqlc.arg('alive'), sqlc.arg('source'), sqlc.arg('ports'));

-- name: ListStagedHosts :many
-- Все staged-строки одного прогона (для отчёта), по возрастанию id.
SELECT id, project_id, job_id, hostname, ip, alive, source, ports, imported, created_at
FROM recon_farm_staged_hosts
WHERE project_id = sqlc.arg('project_id') AND job_id = sqlc.arg('job_id')
ORDER BY id;

-- name: ListStagedHostsByIDs :many
-- Выбранные staged-строки проекта по id (для импорта). Скоуп проекта обязателен —
-- чужие строки не импортируем.
SELECT id, project_id, job_id, hostname, ip, alive, source, ports, imported, created_at
FROM recon_farm_staged_hosts
WHERE project_id = sqlc.arg('project_id') AND id = ANY(sqlc.arg('ids')::int[])
ORDER BY id;

-- name: LatestFarmRunJobID :one
-- id последнего прогона фермы проекта (для отчёта без явного job_id).
SELECT id FROM host_farm_jobs
WHERE project_id = sqlc.arg('project_id') AND kind = 'farm_run'
ORDER BY id DESC
LIMIT 1;

-- name: MarkStagedImported :exec
-- Помечает выбранные staged-строки импортированными (идемпотентно).
UPDATE recon_farm_staged_hosts SET imported = true
WHERE project_id = sqlc.arg('project_id') AND id = ANY(sqlc.arg('ids')::int[]);

-- name: ClearStagedHosts :execrows
-- Удаляет staged-строки одного прогона; возвращает число удалённых.
DELETE FROM recon_farm_staged_hosts
WHERE project_id = sqlc.arg('project_id') AND job_id = sqlc.arg('job_id');

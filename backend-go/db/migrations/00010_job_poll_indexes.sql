-- Композитные индексы под горячий путь поллеров воркеров. Дорожки recon-worker
-- (regular + farm) и mail-worker опрашивают очереди каждые ~5с: выборка pending и
-- реклейм застрявших. На host_farm_jobs были только одиночные индексы (project_id,
-- kind, status) — они НЕ покрывают связку (status,kind)+ORDER BY created_at (poll) и
-- (status,kind,updated_at) (reclaim), поэтому каждый тик шёл в seq scan по мере роста
-- таблицы истории прогонов. Индексы аддитивные (только ускоряют чтение).

-- +goose Up
-- Poll: WHERE (status IN pending|failed) AND kind [=|<>] ? ORDER BY created_at ASC.
CREATE INDEX IF NOT EXISTS ix_host_farm_jobs_poll ON host_farm_jobs (status, kind, created_at);
-- Reclaim: WHERE status IN (queued,running) AND kind [=|<>] ? AND updated_at < ?.
CREATE INDEX IF NOT EXISTS ix_host_farm_jobs_reclaim ON host_farm_jobs (status, kind, updated_at);
-- mail-worker claim: WHERE status IN (pending|failed) ORDER BY created_at ASC.
CREATE INDEX IF NOT EXISTS ix_mail_jobs_claim ON mail_jobs (status, created_at);

-- +goose Down
DROP INDEX IF EXISTS ix_host_farm_jobs_poll;
DROP INDEX IF EXISTS ix_host_farm_jobs_reclaim;
DROP INDEX IF EXISTS ix_mail_jobs_claim;

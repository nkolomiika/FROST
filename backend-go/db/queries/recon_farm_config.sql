-- Контекст recon: пер-проектная конфигурация фермы. GetReconFarmConfig отдаёт
-- сырой JSONB-блоб (Go доклеивает дефолты), Upsert — идемпотентная запись.

-- name: GetReconFarmConfig :one
SELECT config FROM recon_farm_config WHERE project_id = $1;

-- name: UpsertReconFarmConfig :exec
INSERT INTO recon_farm_config (project_id, config, updated_at)
VALUES ($1, $2, now())
ON CONFLICT (project_id) DO UPDATE SET config = EXCLUDED.config, updated_at = now();

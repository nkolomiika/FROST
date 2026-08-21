-- Контекст recon: прогресс полного прогона фермы (kind='farm_run'). Раннер пишет
-- сюда JSON-блоб {stage, percent, steps[], счётчики} по мере продвижения стадий,
-- а GET .../recon/farm/run/{job_id} отдаёт его для живой панели во фронте.

-- +goose Up
ALTER TABLE host_farm_jobs ADD COLUMN progress JSON;

-- +goose Down
ALTER TABLE host_farm_jobs DROP COLUMN IF EXISTS progress;

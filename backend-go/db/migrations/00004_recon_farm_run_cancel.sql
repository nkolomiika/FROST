-- Контекст recon: отмена полного прогона фермы (kind='farm_run'). API-контейнер и
-- recon-worker живут в РАЗНЫХ процессах и общаются только через Postgres, поэтому
-- отмена сигналится через БД: HTTP-хендлер выставляет cancel_requested (весь прогон)
-- или добавляет id шага в cancel_steps (один процесс), а поллер внутри runFarm в
-- воркере читает эти колонки (~раз в 2с) и рвёт соответствующий context.

-- +goose Up
ALTER TABLE host_farm_jobs ADD COLUMN cancel_requested BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE host_farm_jobs ADD COLUMN cancel_steps JSON;

-- +goose Down
ALTER TABLE host_farm_jobs DROP COLUMN IF EXISTS cancel_steps;
ALTER TABLE host_farm_jobs DROP COLUMN IF EXISTS cancel_requested;

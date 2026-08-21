-- Контекст recon: пер-проектная конфигурация фермы (recon-стек). Хранится как
-- JSONB-блоб (typed FarmConfig на стороне Go); дефолты доклеиваются при чтении.

-- +goose Up
CREATE TABLE recon_farm_config (
  project_id INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
  config     JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS recon_farm_config;

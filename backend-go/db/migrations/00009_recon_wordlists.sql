-- Контекст recon: пользовательские СЛОВАРИ (кастомные wordlists), workspace-level.
-- Байты файла лежат в MinIO под СЕРВЕРНЫМ ключом object_key = 'wordlists/{uuid}'
-- (имя файла пользователя НИКОГДА не попадает в путь — только в name как ярлык).
-- Ферма использует их для брута поддоменов (dnsx -w) и дир-фаззинга (ffuf -w) через
-- MaterializeWordlist, который стримит объект во временный серверный файл. Бандл-тиры
-- (small|medium|large, n0kovo) здесь НЕ хранятся — они забандлены в образ.

-- +goose Up
CREATE TABLE recon_wordlists (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    object_key  TEXT NOT NULL UNIQUE,
    size_bytes  BIGINT,
    lines       INT,
    uploaded_by INT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_recon_wordlists_created ON recon_wordlists (created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS recon_wordlists;

-- Контекст leaks: ЕДИНОЕ хранилище утечек (leaked secrets, ключи, креды), в которое
-- пишут РАЗНЫЕ источники — github (trufflehog), позже linkedin, breach-БД (hibp/
-- dehashed/intelx/leakcheck/snusbase/proxynova). Сканеры кладут находки сюда, в
-- «карантин» проекта; пользователь смотрит их (GET .../leaks), импортирует выбранное
-- в проект (создаются project_notes) и чистит. detail — JSONB с полями источника
-- (для github: {repo,file,link,detector,verified}).
--   source ∈ {github, linkedin, hibp, dehashed, intelx, leakcheck, snusbase, proxynova, …}
--   kind   ∈ {secret, credential, key, …}
--   subject = аккаунт/email/репозиторий, к которому относится утечка
--   value   = сам секрет/пароль/токен

-- +goose Up
CREATE TABLE recon_leaks (
    id         SERIAL PRIMARY KEY,
    project_id INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    job_id     INT,
    source     TEXT NOT NULL,
    kind       TEXT NOT NULL,
    subject    TEXT,
    value      TEXT,
    detail     JSONB,
    verified   BOOLEAN NOT NULL DEFAULT false,
    imported   BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_recon_leaks_project ON recon_leaks (project_id);
CREATE INDEX idx_recon_leaks_project_source ON recon_leaks (project_id, source);

-- +goose Down
DROP TABLE IF EXISTS recon_leaks;

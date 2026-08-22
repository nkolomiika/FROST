-- Контекст recon: СТЕЙДЖИНГ новых стадий полного прогона фермы (kind='farm_run') —
-- эндпоинты (katana/gau/waybackurls) и JS-майнинг (trufflehog + regex). Как и хосты
-- (00005), эти находки НЕ пишутся прямо в проект: прогон складывает их сюда, в
-- «карантин», а пользователь смотрит отчёт (GET .../recon/farm/report) и вручную
-- импортирует выбранное (POST .../recon/farm/report/import).
--
--   recon_farm_staged_endpoints — по строке на найденный URL (host+url+method+source).
--   recon_farm_staged_js         — по строке на находку JS-майнинга: kind='secret'
--                                  (value=preview, severity) либо kind='endpoint'
--                                  (value=path). Импорт эндпоинтов создаёт реальные
--                                  endpoints проекта; импорт JS — js_files/secrets.

-- +goose Up
CREATE TABLE recon_farm_staged_endpoints (
    id         SERIAL PRIMARY KEY,
    project_id INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    job_id     INT NOT NULL,
    host       TEXT NOT NULL,
    url        TEXT NOT NULL,
    method     TEXT,
    source     TEXT,
    imported   BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_recon_farm_staged_endpoints_project_job ON recon_farm_staged_endpoints (project_id, job_id);

CREATE TABLE recon_farm_staged_js (
    id         SERIAL PRIMARY KEY,
    project_id INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    job_id     INT NOT NULL,
    host       TEXT NOT NULL,
    url        TEXT NOT NULL,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    severity   TEXT,
    imported   BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_recon_farm_staged_js_project_job ON recon_farm_staged_js (project_id, job_id);

-- +goose Down
DROP TABLE IF EXISTS recon_farm_staged_js;
DROP TABLE IF EXISTS recon_farm_staged_endpoints;

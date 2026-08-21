-- Контекст recon: СТЕЙДЖИНГ полного прогона фермы (kind='farm_run'). Прогон больше
-- НЕ пишет находки прямо в проект (hosts/ips/ports/services) — всё, что он открыл
-- (поддомены, резолв IP, живость, порты, сервисы nmap -sV), складывается сюда, в
-- «карантин». Пользователь смотрит отчёт (GET .../recon/farm/report) и вручную
-- импортирует выбранные строки (POST .../recon/farm/report/import), после чего они
-- становятся реальными хостами проекта, а staged-строки помечаются imported=true.
-- ports — JSONB-массив {port,proto,state,service,version,http_status}.

-- +goose Up
CREATE TABLE recon_farm_staged_hosts (
    id         SERIAL PRIMARY KEY,
    project_id INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    job_id     INT NOT NULL,
    hostname   TEXT NOT NULL,
    ip         TEXT,
    alive      BOOLEAN NOT NULL DEFAULT false,
    source     TEXT,
    ports      JSONB,
    imported   BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_recon_farm_staged_hosts_project ON recon_farm_staged_hosts (project_id);
CREATE INDEX idx_recon_farm_staged_hosts_project_job ON recon_farm_staged_hosts (project_id, job_id);

-- +goose Down
DROP TABLE IF EXISTS recon_farm_staged_hosts;

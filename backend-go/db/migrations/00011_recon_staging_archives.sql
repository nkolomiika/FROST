-- Автономная архивация «холодного» стейджинга ферм-прогонов. Основной объём
-- нареконенных данных — это staged-строки прогонов (recon_farm_staged_hosts/
-- endpoints/js): по строке на каждый найденный хост/URL/секрет. Для завершённых
-- прогонов старше N дней recon-worker фоново выгружает их в один gzip-объект в
-- MinIO (ключ object_key), удаляет строки из БД и пишет сюда запись-указатель.
-- При открытии отчёта такого прогона данные ПРОЗРАЧНО подтягиваются обратно из
-- MinIO (регидрация: строки восстанавливаются, запись здесь удаляется). Так БД не
-- пухнет от истории, а данные остаются доступны по требованию.

-- +goose Up
CREATE TABLE recon_staging_archives (
    job_id          INTEGER PRIMARY KEY REFERENCES host_farm_jobs(id) ON DELETE CASCADE,
    project_id      INTEGER NOT NULL,
    object_key      TEXT NOT NULL,
    size_bytes      BIGINT,
    hosts_count     INTEGER NOT NULL DEFAULT 0,
    endpoints_count INTEGER NOT NULL DEFAULT 0,
    js_count        INTEGER NOT NULL DEFAULT 0,
    archived_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS recon_staging_archives;

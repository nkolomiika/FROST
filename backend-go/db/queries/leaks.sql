-- Контекст leaks: единое хранилище утечек (recon_leaks). Пишут разные источники
-- (source=github|linkedin|hibp|…); чтение/импорт/очистка — по проекту с
-- необязательными фильтрами source/job_id. Импорт создаёт project_notes.

-- name: InsertLeak :exec
INSERT INTO recon_leaks (project_id, job_id, source, kind, subject, value, detail, verified)
VALUES (sqlc.arg('project_id'), sqlc.narg('job_id'), sqlc.arg('source'), sqlc.arg('kind'),
        sqlc.narg('subject'), sqlc.narg('value'), sqlc.arg('detail'), sqlc.arg('verified'));

-- name: ListLeaks :many
-- Все утечки проекта с необязательными фильтрами source/job_id (NULL = не фильтруем).
SELECT id, project_id, job_id, source, kind, subject, value, detail, verified, imported, created_at
FROM recon_leaks
WHERE project_id = sqlc.arg('project_id')
  AND (sqlc.narg('source')::text IS NULL OR source = sqlc.narg('source'))
  AND (sqlc.narg('job_id')::int IS NULL OR job_id = sqlc.narg('job_id'))
ORDER BY id;

-- name: ListLeaksByIDs :many
-- Выбранные утечки проекта по id (для импорта). Скоуп проекта обязателен.
SELECT id, project_id, job_id, source, kind, subject, value, detail, verified, imported, created_at
FROM recon_leaks
WHERE project_id = sqlc.arg('project_id') AND id = ANY(sqlc.arg('ids')::int[])
ORDER BY id;

-- name: MarkLeaksImported :exec
-- Помечает выбранные утечки импортированными (идемпотентно).
UPDATE recon_leaks SET imported = true
WHERE project_id = sqlc.arg('project_id') AND id = ANY(sqlc.arg('ids')::int[]);

-- name: ClearLeaks :execrows
-- Удаляет утечки проекта с необязательными фильтрами source/job_id; число удалённых.
DELETE FROM recon_leaks
WHERE project_id = sqlc.arg('project_id')
  AND (sqlc.narg('source')::text IS NULL OR source = sqlc.narg('source'))
  AND (sqlc.narg('job_id')::int IS NULL OR job_id = sqlc.narg('job_id'));

-- name: InsertLeakNote :exec
-- Лёгкий персист импорта: одна страница-заметка на утечку. title уникален (id
-- утечки в заголовке), parent_id=NULL, sort_order — следующий на верхнем уровне.
INSERT INTO project_notes (project_id, parent_id, title, content, sort_order, created_by, updated_by)
VALUES (
    sqlc.arg('project_id'), NULL, sqlc.arg('title'), sqlc.arg('content'),
    COALESCE((SELECT MAX(sort_order) + 1 FROM project_notes WHERE project_id = sqlc.arg('project_id') AND parent_id IS NULL), 0),
    sqlc.arg('created_by'), sqlc.arg('created_by')
);

-- Контекст recon: пользовательские словари (recon_wordlists), workspace-level.
-- object_key — серверный ключ MinIO ('wordlists/{uuid}'); name — ярлык (имя файла
-- пользователя), в путь НЕ идёт. Читаются списком (GET), точечно по id (материализация
-- / удаление), пишутся при загрузке, удаляются вместе с объектом MinIO.

-- name: InsertWordlist :one
INSERT INTO recon_wordlists (name, object_key, size_bytes, lines, uploaded_by)
VALUES (sqlc.arg('name'), sqlc.arg('object_key'), sqlc.narg('size_bytes'),
        sqlc.narg('lines'), sqlc.narg('uploaded_by'))
RETURNING id, name, object_key, size_bytes, lines, uploaded_by, created_at;

-- name: ListWordlists :many
-- Все кастомные словари workspace (новые сверху).
SELECT id, name, object_key, size_bytes, lines, uploaded_by, created_at
FROM recon_wordlists
ORDER BY created_at DESC, id DESC;

-- name: GetWordlist :one
-- Один словарь по id (для материализации / удаления).
SELECT id, name, object_key, size_bytes, lines, uploaded_by, created_at
FROM recon_wordlists
WHERE id = sqlc.arg('id');

-- name: DeleteWordlist :execrows
-- Удаляет строку словаря по id; число удалённых (0 = не было).
DELETE FROM recon_wordlists WHERE id = sqlc.arg('id');

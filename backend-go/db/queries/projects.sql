-- Запросы контекста projects: проекты, папки, участники, заметки(+комментарии),
-- креды, hidden-ips, статистика, активность, уведомления, упоминания.

-- ─────────── projects ───────────
-- name: GetProjectByID :one
SELECT * FROM projects WHERE id = $1;

-- name: ListProjectsAdmin :many
SELECT * FROM projects
WHERE (sqlc.narg('status')::project_status IS NULL OR status = sqlc.narg('status'))
ORDER BY created_at DESC OFFSET sqlc.arg('offset') LIMIT sqlc.arg('lim');

-- name: CountProjectsAdmin :one
SELECT count(*) FROM projects
WHERE (sqlc.narg('status')::project_status IS NULL OR status = sqlc.narg('status'));

-- name: ListProjectsForMember :many
SELECT p.* FROM projects p JOIN project_members m ON m.project_id = p.id
WHERE m.user_id = sqlc.arg('user_id')
  AND (sqlc.narg('status')::project_status IS NULL OR p.status = sqlc.narg('status'))
ORDER BY p.created_at DESC OFFSET sqlc.arg('offset') LIMIT sqlc.arg('lim');

-- name: CountProjectsForMember :one
SELECT count(*) FROM projects p JOIN project_members m ON m.project_id = p.id
WHERE m.user_id = sqlc.arg('user_id')
  AND (sqlc.narg('status')::project_status IS NULL OR p.status = sqlc.narg('status'));

-- name: InsertProject :one
INSERT INTO projects (name, folder, description, start_date, end_date, status, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;

-- name: UpdateProject :one
UPDATE projects
SET name = $2, folder = $3, description = $4, start_date = $5, end_date = $6,
    status = $7, timeline_frozen_at = $8, updated_at = now()
WHERE id = $1 RETURNING *;

-- name: DeleteProject :exec
DELETE FROM projects WHERE id = $1;

-- name: IsProjectMember :one
SELECT EXISTS (SELECT 1 FROM project_members WHERE project_id = $1 AND user_id = $2);

-- ─────────── project stats ───────────
-- name: ProjectStatsAdmin :many
SELECT p.id AS project_id, p.status,
       COALESCE(h.cnt, 0)::bigint AS hosts_count,
       COALESCE(v.total, 0)::bigint AS total_findings,
       COALESCE(v.open, 0)::bigint AS open_findings
FROM projects p
LEFT JOIN (SELECT project_id, count(*) AS cnt FROM hosts GROUP BY project_id) h ON h.project_id = p.id
LEFT JOIN (SELECT project_id, count(*) AS total,
                  count(*) FILTER (WHERE status IN ('OPEN','IN_PROGRESS')) AS open
           FROM vulnerabilities GROUP BY project_id) v ON v.project_id = p.id
ORDER BY p.created_at DESC;

-- name: ProjectStatsForMember :many
SELECT p.id AS project_id, p.status,
       COALESCE(h.cnt, 0)::bigint AS hosts_count,
       COALESCE(v.total, 0)::bigint AS total_findings,
       COALESCE(v.open, 0)::bigint AS open_findings
FROM projects p
JOIN project_members m ON m.project_id = p.id AND m.user_id = $1
LEFT JOIN (SELECT project_id, count(*) AS cnt FROM hosts GROUP BY project_id) h ON h.project_id = p.id
LEFT JOIN (SELECT project_id, count(*) AS total,
                  count(*) FILTER (WHERE status IN ('OPEN','IN_PROGRESS')) AS open
           FROM vulnerabilities GROUP BY project_id) v ON v.project_id = p.id
ORDER BY p.created_at DESC;

-- ─────────── folders ───────────
-- name: ListFolders :many
SELECT * FROM project_folders ORDER BY path ASC;

-- name: GetFolderByID :one
SELECT * FROM project_folders WHERE id = $1;

-- name: GetFolderByPath :one
SELECT * FROM project_folders WHERE path = $1;

-- name: InsertFolder :one
INSERT INTO project_folders (name, path, parent_id, created_by) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: FindSiblingFolderByName :one
SELECT * FROM project_folders
WHERE parent_id IS NOT DISTINCT FROM sqlc.narg('parent_id') AND name = sqlc.arg('name') AND id <> sqlc.arg('exclude_id')
LIMIT 1;

-- name: ListSubtreeFolders :many
SELECT * FROM project_folders WHERE path = $1 OR path LIKE $1 || '/%';

-- name: ListSubtreeProjects :many
SELECT * FROM projects WHERE folder = $1 OR folder LIKE $1 || '/%';

-- name: UpdateFolderPathParent :exec
UPDATE project_folders SET path = $2, parent_id = $3, updated_at = now() WHERE id = $1;

-- name: UpdateFolderPath :exec
UPDATE project_folders SET path = $2, updated_at = now() WHERE id = $1;

-- name: UpdateProjectFolderPath :exec
UPDATE projects SET folder = $2, updated_at = now() WHERE id = $1;

-- name: DeleteSubtreeProjects :exec
DELETE FROM projects WHERE folder = $1 OR folder LIKE $1 || '/%';

-- name: DeleteSubtreeFolders :exec
DELETE FROM project_folders WHERE path = $1 OR path LIKE $1 || '/%';

-- ─────────── members ───────────
-- name: ListMembers :many
SELECT m.user_id, u.username, u.email, u.role, u.project_role, m.added_at
FROM project_members m JOIN users u ON u.id = m.user_id
WHERE m.project_id = $1 ORDER BY m.added_at DESC;

-- name: GetMember :one
SELECT * FROM project_members WHERE project_id = $1 AND user_id = $2;

-- name: InsertMember :one
INSERT INTO project_members (project_id, user_id) VALUES ($1, $2) RETURNING *;

-- name: DeleteMember :exec
DELETE FROM project_members WHERE project_id = $1 AND user_id = $2;

-- name: ListMemberUserIDs :many
SELECT user_id FROM project_members WHERE project_id = $1;

-- ─────────── notes ───────────
-- name: ListNotes :many
SELECT n.*, u.username AS created_by_username
FROM project_notes n LEFT JOIN users u ON u.id = n.created_by
WHERE n.project_id = $1
ORDER BY n.parent_id ASC NULLS FIRST, n.sort_order ASC, n.title ASC;

-- name: GetNote :one
SELECT n.*, u.username AS created_by_username
FROM project_notes n LEFT JOIN users u ON u.id = n.created_by
WHERE n.id = $1 AND n.project_id = $2;

-- name: FindSiblingNoteTitle :one
SELECT id FROM project_notes
WHERE project_id = sqlc.arg('project_id')
  AND parent_id IS NOT DISTINCT FROM sqlc.narg('parent_id')
  AND title = sqlc.arg('title')
  AND id <> sqlc.arg('exclude_id')
LIMIT 1;

-- name: MaxSiblingSortOrder :one
SELECT COALESCE(MAX(sort_order), -1)::int FROM project_notes
WHERE project_id = sqlc.arg('project_id') AND parent_id IS NOT DISTINCT FROM sqlc.narg('parent_id');

-- name: ListSiblingNotes :many
SELECT n.*, u.username AS created_by_username
FROM project_notes n LEFT JOIN users u ON u.id = n.created_by
WHERE n.project_id = sqlc.arg('project_id') AND n.parent_id IS NOT DISTINCT FROM sqlc.narg('parent_id')
ORDER BY n.sort_order ASC, n.title ASC;

-- name: InsertNote :one
INSERT INTO project_notes (project_id, parent_id, title, content, sort_order, created_by, updated_by)
VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING *;

-- name: UpdateNote :exec
UPDATE project_notes SET title = $2, content = $3, updated_by = $4, updated_at = now() WHERE id = $1;

-- name: MoveNote :exec
UPDATE project_notes SET parent_id = $2, sort_order = $3, updated_by = $4, updated_at = now() WHERE id = $1;

-- name: SetNoteSortOrder :exec
UPDATE project_notes SET sort_order = $2, updated_by = $3, updated_at = now() WHERE id = $1;

-- name: DeleteNote :exec
DELETE FROM project_notes WHERE id = $1;

-- ─────────── note comments ───────────
-- name: CountNoteComments :one
SELECT count(*) FROM project_note_comments WHERE project_id = $1 AND note_id = $2;

-- name: ListNoteComments :many
SELECT c.*, u.username,
       u.avatar_minio_key, u.avatar_uploaded_at, u.id AS uid
FROM project_note_comments c JOIN users u ON u.id = c.user_id
WHERE c.project_id = $1 AND c.note_id = $2
ORDER BY c.created_at ASC OFFSET $3 LIMIT $4;

-- name: GetNoteComment :one
SELECT * FROM project_note_comments WHERE id = $1 AND note_id = $2 AND project_id = $3;

-- name: InsertNoteComment :one
INSERT INTO project_note_comments (project_id, note_id, user_id, content) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: UpdateNoteComment :exec
UPDATE project_note_comments SET content = $2, updated_at = now() WHERE id = $1;

-- name: DeleteNoteComment :exec
DELETE FROM project_note_comments WHERE id = $1;

-- ─────────── credentials ───────────
-- name: ListCredentials :many
SELECT c.*, u.username AS created_by_username
FROM project_credentials c LEFT JOIN users u ON u.id = c.created_by
WHERE c.project_id = $1 ORDER BY c.created_at ASC, c.id ASC;

-- name: GetCredential :one
SELECT c.*, u.username AS created_by_username
FROM project_credentials c LEFT JOIN users u ON u.id = c.created_by
WHERE c.id = $1 AND c.project_id = $2;

-- name: InsertCredential :one
INSERT INTO project_credentials (project_id, username, password_encrypted, host, created_by)
VALUES ($1, $2, $3, $4, $5) RETURNING *;

-- name: UpdateCredential :exec
UPDATE project_credentials SET username = $2, password_encrypted = $3, host = $4, updated_at = now() WHERE id = $1;

-- name: DeleteCredential :exec
DELETE FROM project_credentials WHERE id = $1;

-- ─────────── hidden ips ───────────
-- name: ListHiddenIPs :many
SELECT ip_address FROM project_hidden_ips WHERE project_id = $1 ORDER BY ip_address;

-- name: HiddenIPExists :one
SELECT EXISTS (SELECT 1 FROM project_hidden_ips WHERE project_id = $1 AND ip_address = $2);

-- name: InsertHiddenIP :exec
INSERT INTO project_hidden_ips (project_id, ip_address, created_by) VALUES ($1, $2, $3)
ON CONFLICT ON CONSTRAINT uq_project_hidden_ip DO NOTHING;

-- name: BulkInsertHiddenIPs :execrows
-- Пакетное скрытие адресов: апсерт по (project_id, ip_address) для списка адресов
-- (ON CONFLICT DO NOTHING). Возвращает число реально добавленных (уже скрытые не
-- считаются). Зеркало InsertHiddenIP для множества адресов.
INSERT INTO project_hidden_ips (project_id, ip_address, created_by)
SELECT sqlc.arg('project_id'), unnest(sqlc.arg('addrs')::text[]), sqlc.arg('created_by')
ON CONFLICT ON CONSTRAINT uq_project_hidden_ip DO NOTHING;

-- name: DeleteHiddenIP :exec
DELETE FROM project_hidden_ips WHERE project_id = $1 AND ip_address = $2;

-- name: ListStandaloneIPHostIDs :many
SELECT DISTINCT h.id FROM hosts h JOIN host_ip_addresses hia ON hia.host_id = h.id
WHERE h.project_id = $1 AND h.origin = 'ip' AND hia.ip_address = $2;

-- name: DeleteHostByID :exec
DELETE FROM hosts WHERE id = $1;

-- ─────────── notifications + mentions ───────────
-- name: InsertNotification :exec
INSERT INTO notifications (user_id, type, comment_id, note_comment_id, project_id, vulnerability_id, actor_id, status, is_read)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false);

-- name: ResolveMentionUsers :many
SELECT u.id, u.username FROM users u
LEFT JOIN project_members pm ON pm.user_id = u.id AND pm.project_id = $1
WHERE u.username = ANY(sqlc.arg('usernames')::text[]) AND (pm.user_id IS NOT NULL OR u.role = 'ADMIN');

-- ─────────── activity ───────────
-- name: ListNotesActivity :many
SELECT a.id, a.action, a.entity_id, a.user_id, u.username, a.details, a.created_at
FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id
WHERE a.entity_type = 'project_note' AND a.action IN ('CREATE','UPDATE','DELETE')
  AND (a.details->>'project_id' = $1::text
       OR a.entity_id IN (SELECT id FROM project_notes WHERE project_id = $1))
ORDER BY a.created_at DESC LIMIT $2;

-- name: ListProjectActivity :many
SELECT a.id, a.action, a.entity_type, a.entity_id, a.user_id, u.username, a.details, a.created_at
FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id
WHERE a.entity_type IS NOT NULL
  AND (
    (a.entity_type = 'project' AND a.entity_id = @project_id)
    OR (a.entity_type = 'vulnerability' AND a.entity_id IN (SELECT id FROM vulnerabilities WHERE project_id = @project_id))
    OR (a.entity_type = 'host' AND a.entity_id IN (SELECT id FROM hosts WHERE project_id = @project_id))
    OR (a.entity_type = 'port' AND a.entity_id IN (SELECT id FROM ports WHERE host_id IN (SELECT id FROM hosts WHERE project_id = @project_id)))
    OR (a.entity_type = 'service' AND a.entity_id IN (SELECT id FROM services WHERE port_id IN (SELECT id FROM ports WHERE host_id IN (SELECT id FROM hosts WHERE project_id = @project_id))))
    OR (a.entity_type = 'endpoint' AND a.entity_id IN (SELECT id FROM endpoints WHERE host_id IN (SELECT id FROM hosts WHERE project_id = @project_id)))
    OR (a.entity_type = 'project_note' AND a.entity_id IN (SELECT id FROM project_notes WHERE project_id = @project_id))
    OR (a.entity_type = 'project_member' AND a.entity_id IN (SELECT id FROM project_members WHERE project_id = @project_id))
    OR (a.details->>'project_id' = @project_id::text)
  )
ORDER BY a.created_at DESC LIMIT sqlc.arg('lim');

-- name: ListVulnsForActivity :many
SELECT id, title, severity FROM vulnerabilities WHERE id = ANY(sqlc.arg('ids')::int[]);

-- name: ListProjectsByIDs :many
SELECT * FROM projects WHERE id = ANY(sqlc.arg('ids')::int[]) ORDER BY created_at DESC;

-- name: ListAllProjectIDs :many
SELECT id FROM projects ORDER BY id;

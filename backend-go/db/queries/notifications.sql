-- Контекст notifications (читающая сторона; запись — в projects/vulns контекстах).

-- name: ListNotifications :many
SELECT * FROM notifications
WHERE user_id = $1
  AND (sqlc.narg('is_read')::bool IS NULL OR is_read = sqlc.narg('is_read'))
ORDER BY created_at DESC
OFFSET sqlc.arg('offset') LIMIT sqlc.arg('lim');

-- name: CountNotifications :one
SELECT count(*) FROM notifications
WHERE user_id = $1
  AND (sqlc.narg('is_read')::bool IS NULL OR is_read = sqlc.narg('is_read'));

-- name: CountUnreadNotifications :one
SELECT count(*) FROM notifications WHERE user_id = $1 AND is_read = false;

-- name: MarkNotificationRead :one
UPDATE notifications SET is_read = true WHERE id = $1 AND user_id = $2 RETURNING *;

-- name: MarkAllNotificationsRead :exec
UPDATE notifications SET is_read = true WHERE user_id = $1;

-- ─────────── резолверы контекста ───────────

-- name: GetCommentNotificationContext :one
SELECT c.vulnerability_id AS vulnerability_id, v.title AS title, v.project_id AS project_id, u.username AS username
FROM comments c
JOIN vulnerabilities v ON v.id = c.vulnerability_id
JOIN users u ON u.id = c.user_id
WHERE c.id = $1;

-- name: GetCommentHostID :one
SELECT va.asset_id
FROM vulnerability_assets va
JOIN comments c ON c.vulnerability_id = va.vulnerability_id
WHERE va.asset_type = 'HOST' AND c.id = $1
LIMIT 1;

-- name: GetNoteCommentNotificationContext :one
SELECT pnc.note_id, pnc.project_id, u.username, pn.title AS note_title
FROM project_note_comments pnc
JOIN project_notes pn ON pn.id = pnc.note_id
JOIN users u ON u.id = pnc.user_id
WHERE pnc.id = $1;

-- name: GetVulnTitleAndProject :one
SELECT title, project_id FROM vulnerabilities WHERE id = $1;

-- name: GetProjectName :one
SELECT name FROM projects WHERE id = $1;

-- name: GetUsernameByID :one
SELECT username FROM users WHERE id = $1;

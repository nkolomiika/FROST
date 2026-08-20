-- Контекст vulns: vulnerabilities (+CVSS 4.0), assets, comments/mentions, files.

-- ─────────── vulnerabilities ───────────
-- name: GetVuln :one
SELECT v.*, u.username AS created_by_username
FROM vulnerabilities v LEFT JOIN users u ON u.id = v.created_by
WHERE v.id = $1 AND v.project_id = $2;

-- name: ListVulns :many
SELECT v.*, u.username AS created_by_username
FROM vulnerabilities v LEFT JOIN users u ON u.id = v.created_by
WHERE v.project_id = sqlc.arg('project_id')
  AND (sqlc.narg('severity')::vuln_severity IS NULL OR v.severity = sqlc.narg('severity'))
  AND (sqlc.narg('status')::vuln_status IS NULL OR v.status = sqlc.narg('status'))
ORDER BY v.created_at DESC OFFSET sqlc.arg('offset') LIMIT sqlc.arg('lim');

-- name: CountVulns :one
SELECT count(*) FROM vulnerabilities v
WHERE v.project_id = sqlc.arg('project_id')
  AND (sqlc.narg('severity')::vuln_severity IS NULL OR v.severity = sqlc.narg('severity'))
  AND (sqlc.narg('status')::vuln_status IS NULL OR v.status = sqlc.narg('status'));

-- name: ListVulnsForHost :many
SELECT v.*, u.username AS created_by_username
FROM vulnerabilities v
JOIN vulnerability_assets va ON va.vulnerability_id = v.id AND va.asset_type = 'HOST' AND va.asset_id = sqlc.arg('host_id')
LEFT JOIN users u ON u.id = v.created_by
WHERE v.project_id = sqlc.arg('project_id')
  AND (sqlc.narg('severity')::vuln_severity IS NULL OR v.severity = sqlc.narg('severity'))
  AND (sqlc.narg('status')::vuln_status IS NULL OR v.status = sqlc.narg('status'))
ORDER BY v.created_at DESC OFFSET sqlc.arg('offset') LIMIT sqlc.arg('lim');

-- name: CountVulnsForHost :one
SELECT count(*) FROM vulnerabilities v
JOIN vulnerability_assets va ON va.vulnerability_id = v.id AND va.asset_type = 'HOST' AND va.asset_id = sqlc.arg('host_id')
WHERE v.project_id = sqlc.arg('project_id')
  AND (sqlc.narg('severity')::vuln_severity IS NULL OR v.severity = sqlc.narg('severity'))
  AND (sqlc.narg('status')::vuln_status IS NULL OR v.status = sqlc.narg('status'));

-- name: HostExistsInProject :one
SELECT EXISTS (SELECT 1 FROM hosts WHERE id = $1 AND project_id = $2);

-- name: InsertVuln :one
INSERT INTO vulnerabilities (project_id, title, description, severity, cvss_version, cvss_score,
    cvss_vector, cwe_id, status, workflow_steps, steps_to_reproduce, impact, recommendations, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING *;

-- name: UpdateVuln :one
UPDATE vulnerabilities SET title = $2, description = $3, severity = $4, cvss_version = $5,
    cvss_score = $6, cvss_vector = $7, cwe_id = $8, status = $9, workflow_steps = $10,
    steps_to_reproduce = $11, impact = $12, recommendations = $13, updated_at = now()
WHERE id = $1 RETURNING *;

-- name: PatchVulnStatus :one
UPDATE vulnerabilities SET status = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: DeleteVuln :exec
DELETE FROM vulnerabilities WHERE id = $1;

-- ─────────── vulnerability_assets ───────────
-- name: ListVulnAssets :many
SELECT * FROM vulnerability_assets WHERE vulnerability_id = $1 ORDER BY id;

-- name: PrimaryHostID :one
SELECT asset_id FROM vulnerability_assets WHERE vulnerability_id = $1 AND asset_type = 'HOST' ORDER BY id LIMIT 1;

-- name: FindVulnAsset :one
SELECT * FROM vulnerability_assets WHERE vulnerability_id = $1 AND asset_type = $2 AND asset_id = $3;

-- name: GetVulnAssetLink :one
SELECT * FROM vulnerability_assets WHERE id = $1 AND vulnerability_id = $2;

-- name: CountHostAssetLinks :one
SELECT count(*) FROM vulnerability_assets WHERE vulnerability_id = $1 AND asset_type = 'HOST';

-- name: InsertVulnAsset :one
INSERT INTO vulnerability_assets (vulnerability_id, asset_type, asset_id) VALUES ($1, $2, $3) RETURNING *;

-- name: DeleteVulnAsset :exec
DELETE FROM vulnerability_assets WHERE id = $1;

-- asset-in-project existence checks (polymorphic)
-- name: HostAssetInProject :one
SELECT EXISTS (SELECT 1 FROM hosts WHERE id = $1 AND project_id = $2);
-- name: PortAssetInProject :one
SELECT EXISTS (SELECT 1 FROM ports p JOIN hosts h ON h.id = p.host_id WHERE p.id = $1 AND h.project_id = $2);
-- name: ServiceAssetInProject :one
SELECT EXISTS (SELECT 1 FROM services s JOIN ports p ON p.id = s.port_id JOIN hosts h ON h.id = p.host_id WHERE s.id = $1 AND h.project_id = $2);
-- name: EndpointAssetInProject :one
SELECT EXISTS (SELECT 1 FROM endpoints e JOIN hosts h ON h.id = e.host_id WHERE e.id = $1 AND h.project_id = $2);

-- ─────────── comments ───────────
-- name: CountVulnComments :one
SELECT count(*) FROM comments WHERE vulnerability_id = $1;

-- name: ListVulnComments :many
SELECT c.*, u.username, u.avatar_minio_key, u.avatar_uploaded_at
FROM comments c JOIN users u ON u.id = c.user_id
WHERE c.vulnerability_id = $1 ORDER BY c.created_at ASC OFFSET $2 LIMIT $3;

-- name: GetVulnComment :one
SELECT * FROM comments WHERE id = $1 AND vulnerability_id = $2;

-- name: InsertVulnComment :one
INSERT INTO comments (vulnerability_id, user_id, content) VALUES ($1, $2, $3) RETURNING *;

-- name: UpdateVulnComment :exec
UPDATE comments SET content = $2, updated_at = now() WHERE id = $1;

-- name: DeleteVulnComment :exec
DELETE FROM comments WHERE id = $1;

-- ─────────── comment mentions ───────────
-- name: ResolveCommentMentionUsers :many
SELECT u.id, u.username FROM users u
LEFT JOIN project_members pm ON pm.user_id = u.id AND pm.project_id = $1
WHERE u.username = ANY(sqlc.arg('usernames')::text[]) AND (pm.user_id IS NOT NULL OR u.role = 'ADMIN');

-- name: InsertCommentMention :exec
INSERT INTO comment_mentions (comment_id, user_id) VALUES ($1, $2)
ON CONFLICT ON CONSTRAINT uq_comment_mention DO NOTHING;

-- name: ClearCommentMentions :exec
DELETE FROM comment_mentions WHERE comment_id = $1;

-- name: ListCommentMentions :many
SELECT cm.user_id, u.username FROM comment_mentions cm JOIN users u ON u.id = cm.user_id
WHERE cm.comment_id = $1 ORDER BY cm.id;

-- ─────────── notifications ───────────
-- name: InsertMentionNotification :exec
INSERT INTO notifications (user_id, type, comment_id, actor_id, is_read)
VALUES ($1, 'MENTION', $2, $3, false);

-- name: InsertVulnStatusNotification :exec
INSERT INTO notifications (user_id, type, vulnerability_id, project_id, actor_id, status, is_read)
VALUES ($1, 'VULN_STATUS_CHANGED', $2, $3, $4, $5, false);

-- ─────────── files ───────────
-- name: ListVulnFiles :many
SELECT * FROM files WHERE vulnerability_id = $1 ORDER BY uploaded_at DESC;

-- name: GetFileByID :one
SELECT * FROM files WHERE id = $1;

-- name: GetFileForVuln :one
SELECT * FROM files WHERE id = $1 AND vulnerability_id = $2;

-- name: InsertFile :one
INSERT INTO files (vulnerability_id, original_name, content_type, size_bytes, minio_bucket, minio_key, uploaded_by)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;

-- name: DeleteFile :exec
DELETE FROM files WHERE id = $1;

-- name: CountFileImagesForVuln :one
SELECT count(*) FROM files WHERE vulnerability_id = $1 AND id = ANY(sqlc.arg('ids')::int[]);

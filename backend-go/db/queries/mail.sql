-- Запросы контекста mail (outbox). Отправка писем — Phase 2 (mail-worker).

-- name: InsertMailJob :one
INSERT INTO mail_jobs (user_id, created_by, recipient_email, subject, template, payload, status)
VALUES ($1, $2, $3, $4, $5, $6, 'pending')
RETURNING *;

-- name: ClaimPendingMailJobs :many
SELECT * FROM mail_jobs WHERE status = 'pending' ORDER BY created_at LIMIT $1;

-- name: MarkMailJobSent :exec
UPDATE mail_jobs SET status = 'sent', sent_at = now() WHERE id = $1;

-- name: MarkMailJobFailed :exec
UPDATE mail_jobs SET status = 'failed', attempts = attempts + 1, last_error = $2 WHERE id = $1;

-- Запросы контекста mail (outbox). Отправка — cmd/mail-worker.
-- Модель статусов (порт mail_worker.py): pending→queued→processing→sent|failed.
-- attempts инкрементится при ВЗЯТИИ в работу (MarkMailJobProcessing), не при провале.

-- name: InsertMailJob :one
INSERT INTO mail_jobs (user_id, created_by, recipient_email, subject, template, payload, status)
VALUES ($1, $2, $3, $4, $5, $6, 'pending')
RETURNING *;

-- name: GetMailJob :one
SELECT * FROM mail_jobs WHERE id = $1;

-- name: ClaimPendingMailJobs :many
SELECT * FROM mail_jobs
WHERE status = 'pending' OR (status = 'failed' AND attempts < sqlc.arg('max_attempts'))
ORDER BY created_at ASC
LIMIT sqlc.arg('lim');

-- name: MarkMailJobQueued :exec
UPDATE mail_jobs SET status = 'queued', published_at = now(), last_error = NULL WHERE id = $1;

-- name: MarkMailJobProcessing :one
UPDATE mail_jobs SET status = 'processing', attempts = attempts + 1
WHERE id = $1 AND status <> 'sent'
RETURNING *;

-- name: MarkMailJobSent :exec
UPDATE mail_jobs SET status = 'sent', sent_at = now(), last_error = NULL WHERE id = $1;

-- name: MarkMailJobPending :exec
UPDATE mail_jobs SET status = 'pending', last_error = $2 WHERE id = $1;

-- name: MarkMailJobFailed :exec
UPDATE mail_jobs SET status = 'failed', last_error = $2 WHERE id = $1;

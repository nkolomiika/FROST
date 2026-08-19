-- Запросы контекста users (роутер users.py). Часть операций переиспользует
-- запросы из auth.sql (GetUserByID/ByUsername/ByEmail, Username/EmailExists,
-- UpdateUserPassword, SetUserLocked/Active, EnableUserTotp/DisableUserTotp,
-- RevokeAllUserRefreshTokens, CreateInvitation, CreateReactivationToken,
-- ExpireUserUnusedReactivationTokens, InsertMailJob, InsertAuditLog).

-- name: ListUsers :many
SELECT * FROM users ORDER BY created_at DESC OFFSET $1 LIMIT $2;

-- name: CountUsers :one
SELECT count(*) FROM users;

-- name: UpdateUserProfile :exec
UPDATE users SET username = $2, email = $3, full_name = $4 WHERE id = $1;

-- name: UpdateUserAdmin :exec
UPDATE users SET full_name = $2, role = $3, project_role = $4, is_active = $5 WHERE id = $1;

-- name: ResetUserPasswordTemp :exec
UPDATE users SET password_hash = $2, password_changed_at = NULL WHERE id = $1;

-- name: SetUserTotpSecretForSetup :exec
UPDATE users SET totp_secret = $2, totp_confirmed_at = NULL WHERE id = $1;

-- name: SetUserAvatar :exec
UPDATE users
SET avatar_minio_bucket = $2, avatar_minio_key = $3, avatar_content_type = $4, avatar_uploaded_at = now()
WHERE id = $1;

-- name: ListPendingInvitations :many
SELECT * FROM invitations WHERE status = 'pending' ORDER BY created_at DESC;

-- name: GetInvitationByID :one
SELECT * FROM invitations WHERE id = $1;

-- name: GetActivePendingInvitationByEmail :one
SELECT * FROM invitations WHERE email = $1 AND status = 'pending' AND expires_at > now() ORDER BY created_at DESC LIMIT 1;

-- name: UpdateInvitationForResend :exec
UPDATE invitations SET token_hash = $2, status = 'pending', expires_at = $3 WHERE id = $1;

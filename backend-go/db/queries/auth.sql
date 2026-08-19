-- Запросы контекста auth. Растут по мере порта роутеров auth/users.
-- Колонки — из baseline (00001_baseline.sql). sqlc-синтаксис имён: `-- name: X :kind`.

-- ─────────────────────────── users ───────────────────────────

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: UsernameExists :one
SELECT EXISTS (SELECT 1 FROM users WHERE username = $1);

-- name: EmailExists :one
SELECT EXISTS (SELECT 1 FROM users WHERE email = $1);

-- name: CreateUser :one
INSERT INTO users (username, email, full_name, password_hash, role, project_role, is_active)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: UpdateUserPassword :exec
UPDATE users
SET password_hash = $2, password_changed_at = now()
WHERE id = $1;

-- name: SetUserLocked :exec
UPDATE users SET is_locked = $2 WHERE id = $1;

-- name: SetUserActive :exec
UPDATE users SET is_active = $2 WHERE id = $1;

-- ─────────────────────────── 2FA (TOTP) ───────────────────────────

-- name: SetUserTotpSecret :exec
UPDATE users SET totp_secret = $2 WHERE id = $1;

-- name: EnableUserTotp :exec
UPDATE users SET totp_enabled = true, totp_confirmed_at = now() WHERE id = $1;

-- name: DisableUserTotp :exec
UPDATE users SET totp_enabled = false, totp_secret = NULL, totp_confirmed_at = NULL WHERE id = $1;

-- ─────────────────────────── refresh_tokens ───────────────────────────

-- name: InsertRefreshToken :one
INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT * FROM refresh_tokens WHERE token_hash = $1;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL;

-- name: RevokeAllUserRefreshTokens :exec
UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens WHERE expires_at < now();

-- ─────────────────────────── invitations ───────────────────────────

-- name: CreateInvitation :one
INSERT INTO invitations (email, full_name, role, project_role, token_hash, status, expires_at, invited_by)
VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)
RETURNING *;

-- name: GetInvitationByTokenHash :one
SELECT * FROM invitations WHERE token_hash = $1;

-- name: GetPendingInvitationByEmail :one
SELECT * FROM invitations WHERE email = $1 AND status = 'pending' ORDER BY created_at DESC LIMIT 1;

-- name: MarkInvitationAccepted :exec
UPDATE invitations
SET status = 'accepted', accepted_at = now(), accepted_user_id = $2
WHERE id = $1;

-- name: RevokeInvitation :exec
UPDATE invitations SET status = 'revoked' WHERE id = $1;

-- ─────────────────────────── password_reset_tokens ───────────────────────────

-- name: CreatePasswordResetToken :one
INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetPasswordResetByHash :one
SELECT * FROM password_reset_tokens WHERE token_hash = $1;

-- name: MarkPasswordResetUsed :exec
UPDATE password_reset_tokens SET used_at = now() WHERE id = $1;

-- ─────────────────────────── account_reactivation_tokens ───────────────────────────

-- name: CreateReactivationToken :one
INSERT INTO account_reactivation_tokens (user_id, token_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetReactivationByHash :one
SELECT * FROM account_reactivation_tokens WHERE token_hash = $1;

-- name: MarkReactivationUsed :exec
UPDATE account_reactivation_tokens SET used_at = now() WHERE id = $1;

-- name: GetRefreshTokenForUser :one
SELECT * FROM refresh_tokens WHERE token_hash = $1 AND user_id = $2;

-- name: ExpireUserUnusedPasswordResetTokens :exec
UPDATE password_reset_tokens SET used_at = now() WHERE user_id = $1 AND used_at IS NULL;

-- name: ExpireUserUnusedReactivationTokens :exec
UPDATE account_reactivation_tokens SET used_at = now() WHERE user_id = $1 AND used_at IS NULL;

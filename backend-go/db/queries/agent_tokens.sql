-- Запросы контекста agenttokens (v1 CRUD + v2 bearer-auth).

-- name: CreateAgentToken :one
INSERT INTO agent_api_tokens (name, token_hash, token_prefix, scopes, all_projects, created_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: InsertAgentTokenGrant :exec
INSERT INTO agent_api_token_project_grants (token_id, project_id) VALUES ($1, $2)
ON CONFLICT ON CONSTRAINT uq_agent_api_token_project DO NOTHING;

-- name: ListAgentTokenGrants :many
SELECT project_id FROM agent_api_token_project_grants WHERE token_id = $1 ORDER BY project_id;

-- name: ListAgentTokensByCreator :many
SELECT * FROM agent_api_tokens WHERE created_by = $1 ORDER BY created_at DESC;

-- name: GetAgentTokenByID :one
SELECT * FROM agent_api_tokens WHERE id = $1;

-- name: DeleteAgentToken :exec
DELETE FROM agent_api_tokens WHERE id = $1;

-- name: GetAgentTokenByHash :one
SELECT * FROM agent_api_tokens WHERE token_hash = $1;

-- name: TouchAgentTokenLastUsed :exec
UPDATE agent_api_tokens SET last_used_at = $2 WHERE id = $1;

-- name: ListMemberProjectIDs :many
SELECT project_id FROM project_members WHERE user_id = $1;

-- name: GetUserRoleByID :one
SELECT id, role FROM users WHERE id = $1;

-- +goose Up
-- +goose StatementBegin
--
-- Baseline-схема FROST (зеркало SQLAlchemy `Base.metadata.create_all` из
-- backend/app/models.py + сложившихся startup-ALTER'ов из backend/app/main.py).
-- Источник истины на момент старта Go-переписи; дальнейшие изменения — отдельными
-- goose-ревизиями (портируем как явные миграции).
--
-- ВАЖНО про enum'ы: SQLAlchemy `Enum(PyEnum)` хранит ИМЯ члена (в верхнем регистре),
-- а не value. Поэтому типы ниже содержат имена (ADMIN/PENTESTER/INFO/V31/…), как в БД
-- Python-версии. Сериализация в API (lowercase value) — забота HTTP-слоя, не БД.

-- ---------------------------------------------------------------------------
-- Enum-типы
-- ---------------------------------------------------------------------------
CREATE TYPE user_role AS ENUM ('ADMIN', 'PENTESTER');
CREATE TYPE project_role AS ENUM ('LEAD', 'PENTESTER');
CREATE TYPE project_status AS ENUM (
    'ACTIVE', 'FREEZE', 'HANDOVER_TO_DEVELOPMENT', 'VULNERABILITY_RECHECK', 'COMPLETED', 'ARCHIVED'
);
CREATE TYPE host_status AS ENUM ('UP', 'DOWN', 'UNKNOWN');
CREATE TYPE host_os_type AS ENUM (
    'WINDOWS', 'LINUX', 'MACOS', 'FREEBSD', 'ANDROID', 'IOS', 'OTHER', 'UNKNOWN'
);
CREATE TYPE port_protocol AS ENUM ('TCP', 'UDP');
CREATE TYPE port_state AS ENUM ('OPEN', 'CLOSED', 'FILTERED');
CREATE TYPE http_method AS ENUM (
    'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'QUERY'
);
CREATE TYPE vuln_severity AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');
CREATE TYPE cvss_version AS ENUM ('V31', 'V40');
CREATE TYPE vuln_status AS ENUM ('OPEN', 'IN_PROGRESS', 'FIXED', 'WONT_FIX', 'ACCEPTED_RISK');
CREATE TYPE asset_type AS ENUM ('HOST', 'PORT', 'SERVICE', 'ENDPOINT');
CREATE TYPE notification_type AS ENUM (
    'MENTION', 'PROJECT_MEMBER_ADDED', 'VULN_STATUS_CHANGED', 'PROJECT_STATUS_CHANGED'
);

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id                     SERIAL PRIMARY KEY,
    username               VARCHAR(100) NOT NULL,
    email                  VARCHAR(255) NOT NULL,
    full_name              VARCHAR(255),
    avatar_minio_bucket    VARCHAR(63),
    avatar_minio_key       TEXT,
    avatar_content_type    VARCHAR(127),
    avatar_uploaded_at     TIMESTAMP WITH TIME ZONE,
    password_hash          VARCHAR(255) NOT NULL,
    password_changed_at    TIMESTAMP WITH TIME ZONE,
    totp_secret            TEXT,
    totp_enabled           BOOLEAN NOT NULL DEFAULT false,
    totp_confirmed_at      TIMESTAMP WITH TIME ZONE,
    role                   user_role NOT NULL,
    project_role           project_role NOT NULL DEFAULT 'PENTESTER',
    is_active              BOOLEAN NOT NULL,
    is_locked              BOOLEAN NOT NULL DEFAULT false,
    tags                   JSON,
    created_at             TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at             TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ix_users_username ON users (username);
CREATE UNIQUE INDEX ix_users_email ON users (email);

-- ---------------------------------------------------------------------------
-- refresh_tokens
-- ---------------------------------------------------------------------------
CREATE TABLE refresh_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(255) NOT NULL UNIQUE,
    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMP WITH TIME ZONE
);
CREATE INDEX ix_refresh_tokens_token_hash ON refresh_tokens (token_hash);

-- ---------------------------------------------------------------------------
-- projects
-- ---------------------------------------------------------------------------
CREATE TABLE projects (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(255) NOT NULL,
    folder              VARCHAR(255) NOT NULL DEFAULT '',
    description         TEXT,
    start_date          DATE,
    end_date            DATE,
    timeline_frozen_at  TIMESTAMP WITH TIME ZONE,
    status              project_status NOT NULL,
    created_by          INTEGER NOT NULL REFERENCES users(id),
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- agent_api_tokens (+ project grants)
-- ---------------------------------------------------------------------------
CREATE TABLE agent_api_tokens (
    id            SERIAL PRIMARY KEY,
    name          TEXT NOT NULL,
    token_hash    VARCHAR(255) NOT NULL UNIQUE,
    token_prefix  VARCHAR(32) NOT NULL,
    scopes        JSON NOT NULL,
    all_projects  BOOLEAN NOT NULL DEFAULT false,
    created_by    INTEGER NOT NULL REFERENCES users(id),
    expires_at    TIMESTAMP WITH TIME ZONE,
    revoked_at    TIMESTAMP WITH TIME ZONE,
    last_used_at  TIMESTAMP WITH TIME ZONE,
    created_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_agent_api_tokens_token_hash ON agent_api_tokens (token_hash);
CREATE INDEX ix_agent_api_tokens_token_prefix ON agent_api_tokens (token_prefix);

CREATE TABLE agent_api_token_project_grants (
    id          SERIAL PRIMARY KEY,
    token_id    INTEGER NOT NULL REFERENCES agent_api_tokens(id) ON DELETE CASCADE,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT uq_agent_api_token_project UNIQUE (token_id, project_id)
);
CREATE INDEX ix_agent_api_token_project_grants_token_id ON agent_api_token_project_grants (token_id);
CREATE INDEX ix_agent_api_token_project_grants_project_id ON agent_api_token_project_grants (project_id);

-- ---------------------------------------------------------------------------
-- mail_jobs
-- ---------------------------------------------------------------------------
CREATE TABLE mail_jobs (
    id               SERIAL PRIMARY KEY,
    user_id          INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_by       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    recipient_email  VARCHAR(255) NOT NULL,
    subject          VARCHAR(255) NOT NULL,
    template         VARCHAR(100) NOT NULL,
    payload          JSON NOT NULL,
    status           VARCHAR(32) NOT NULL DEFAULT 'pending',
    attempts         INTEGER NOT NULL DEFAULT 0,
    published_at     TIMESTAMP WITH TIME ZONE,
    sent_at          TIMESTAMP WITH TIME ZONE,
    last_error       TEXT,
    created_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_mail_jobs_recipient_email ON mail_jobs (recipient_email);
CREATE INDEX ix_mail_jobs_template ON mail_jobs (template);
CREATE INDEX ix_mail_jobs_status ON mail_jobs (status);

-- ---------------------------------------------------------------------------
-- invitations
-- ---------------------------------------------------------------------------
CREATE TABLE invitations (
    id                SERIAL PRIMARY KEY,
    email             VARCHAR(255) NOT NULL,
    full_name         VARCHAR(255),
    role              user_role NOT NULL,
    project_role      project_role NOT NULL DEFAULT 'PENTESTER',
    token_hash        VARCHAR(255) NOT NULL UNIQUE,
    status            VARCHAR(32) NOT NULL DEFAULT 'pending',
    expires_at        TIMESTAMP WITH TIME ZONE NOT NULL,
    invited_by        INTEGER REFERENCES users(id) ON DELETE SET NULL,
    accepted_at       TIMESTAMP WITH TIME ZONE,
    accepted_user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_invitations_email ON invitations (email);
CREATE INDEX ix_invitations_token_hash ON invitations (token_hash);
CREATE INDEX ix_invitations_status ON invitations (status);

-- ---------------------------------------------------------------------------
-- password_reset_tokens / account_reactivation_tokens
-- ---------------------------------------------------------------------------
CREATE TABLE password_reset_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(255) NOT NULL UNIQUE,
    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at     TIMESTAMP WITH TIME ZONE,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_password_reset_tokens_user_id ON password_reset_tokens (user_id);
CREATE INDEX ix_password_reset_tokens_token_hash ON password_reset_tokens (token_hash);

CREATE TABLE account_reactivation_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(255) NOT NULL UNIQUE,
    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at     TIMESTAMP WITH TIME ZONE,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_account_reactivation_tokens_user_id ON account_reactivation_tokens (user_id);
CREATE INDEX ix_account_reactivation_tokens_token_hash ON account_reactivation_tokens (token_hash);

-- ---------------------------------------------------------------------------
-- project_folders
-- ---------------------------------------------------------------------------
CREATE TABLE project_folders (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    path        VARCHAR(1024) NOT NULL,
    parent_id   INTEGER REFERENCES project_folders(id) ON DELETE CASCADE,
    created_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT uq_project_folder_parent_name UNIQUE (parent_id, name),
    CONSTRAINT uq_project_folder_path UNIQUE (path)
);

-- ---------------------------------------------------------------------------
-- project_members
-- ---------------------------------------------------------------------------
CREATE TABLE project_members (
    id          SERIAL PRIMARY KEY,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT uq_project_member UNIQUE (project_id, user_id)
);

-- ---------------------------------------------------------------------------
-- project_notes (+ comments)
-- ---------------------------------------------------------------------------
CREATE TABLE project_notes (
    id          SERIAL PRIMARY KEY,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    parent_id   INTEGER REFERENCES project_notes(id) ON DELETE CASCADE,
    title       VARCHAR(255) NOT NULL,
    content     TEXT,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    created_by  INTEGER NOT NULL REFERENCES users(id),
    updated_by  INTEGER REFERENCES users(id),
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT uq_project_note_sibling_title UNIQUE (project_id, parent_id, title)
);
CREATE INDEX ix_project_notes_project_id ON project_notes (project_id);
CREATE INDEX ix_project_notes_parent_id ON project_notes (parent_id);

CREATE TABLE project_note_comments (
    id          SERIAL PRIMARY KEY,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    note_id     INTEGER NOT NULL REFERENCES project_notes(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content     TEXT NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_project_note_comments_project_id ON project_note_comments (project_id);
CREATE INDEX ix_project_note_comments_note_id ON project_note_comments (note_id);

-- ---------------------------------------------------------------------------
-- project_credentials
-- ---------------------------------------------------------------------------
CREATE TABLE project_credentials (
    id                  SERIAL PRIMARY KEY,
    project_id          INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    username            VARCHAR(255),
    password_encrypted  TEXT NOT NULL,
    host                VARCHAR(255),
    created_by          INTEGER NOT NULL REFERENCES users(id),
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_project_credentials_project_id ON project_credentials (project_id);

-- ---------------------------------------------------------------------------
-- hosts / host_ip_addresses / ports / services
-- ---------------------------------------------------------------------------
CREATE TABLE hosts (
    id          SERIAL PRIMARY KEY,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ip_address  VARCHAR(45),
    hostname    VARCHAR(255),
    status      host_status NOT NULL,
    os_type     host_os_type NOT NULL DEFAULT 'UNKNOWN',
    notes       TEXT,
    origin      VARCHAR(16) NOT NULL DEFAULT 'host',
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT ck_host_ip_or_hostname CHECK (ip_address IS NOT NULL OR hostname IS NOT NULL)
);
CREATE INDEX ix_hosts_project_id ON hosts (project_id);
CREATE INDEX ix_hosts_origin ON hosts (origin);

CREATE TABLE host_ip_addresses (
    id             SERIAL PRIMARY KEY,
    host_id        INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    ip_address     VARCHAR(45) NOT NULL,
    label          VARCHAR(100),
    is_primary     BOOLEAN NOT NULL DEFAULT false,
    hostnames      JSON,
    is_cloudflare  BOOLEAN,
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT uq_host_ip_address UNIQUE (host_id, ip_address)
);
CREATE INDEX ix_host_ip_addresses_host_id ON host_ip_addresses (host_id);

CREATE TABLE ports (
    id             SERIAL PRIMARY KEY,
    host_id        INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    ip_address_id  INTEGER NOT NULL REFERENCES host_ip_addresses(id) ON DELETE CASCADE,
    port_number    INTEGER NOT NULL,
    protocol       port_protocol NOT NULL,
    state          port_state NOT NULL,
    http_status    INTEGER,
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT uq_port_ip_number_protocol UNIQUE (ip_address_id, port_number, protocol),
    CONSTRAINT ck_port_number_range CHECK (port_number >= 1 AND port_number <= 65535)
);
CREATE INDEX ix_ports_ip_address_id ON ports (ip_address_id);

CREATE TABLE services (
    id          SERIAL PRIMARY KEY,
    port_id     INTEGER NOT NULL REFERENCES ports(id) ON DELETE CASCADE,
    name        VARCHAR(100) NOT NULL,
    version     VARCHAR(100),
    banner      TEXT,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- project_hidden_ips
-- ---------------------------------------------------------------------------
CREATE TABLE project_hidden_ips (
    id          SERIAL PRIMARY KEY,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    ip_address  VARCHAR(45) NOT NULL,
    created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT uq_project_hidden_ip UNIQUE (project_id, ip_address)
);
CREATE INDEX ix_project_hidden_ips_project_id ON project_hidden_ips (project_id);

-- ---------------------------------------------------------------------------
-- host_farm_jobs
-- ---------------------------------------------------------------------------
CREATE TABLE host_farm_jobs (
    id               SERIAL PRIMARY KEY,
    project_id       INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    created_by       INTEGER NOT NULL REFERENCES users(id),
    kind             VARCHAR(16) NOT NULL DEFAULT 'hosts',
    status           VARCHAR(32) NOT NULL DEFAULT 'pending',
    targets_total    INTEGER,
    result           JSON,
    error            TEXT,
    raw              TEXT,
    attempts         INTEGER NOT NULL DEFAULT 0,
    published_at     TIMESTAMP WITH TIME ZONE,
    last_error       TEXT,
    finished_at      TIMESTAMP WITH TIME ZONE,
    skipped_targets  JSON,
    created_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_host_farm_jobs_project_id ON host_farm_jobs (project_id);
CREATE INDEX ix_host_farm_jobs_kind ON host_farm_jobs (kind);
CREATE INDEX ix_host_farm_jobs_status ON host_farm_jobs (status);

-- ---------------------------------------------------------------------------
-- endpoints
-- ---------------------------------------------------------------------------
CREATE TABLE endpoints (
    id                    SERIAL PRIMARY KEY,
    host_id               INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    path                  TEXT NOT NULL,
    method                http_method,
    description           TEXT,
    query_params          JSON,
    request_body          TEXT,
    request_content_type  VARCHAR(127),
    request_headers       JSON,
    created_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_endpoints_host_id ON endpoints (host_id);

-- ---------------------------------------------------------------------------
-- js_files / js_secrets
-- ---------------------------------------------------------------------------
CREATE TABLE js_files (
    id              SERIAL PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    sha256          VARCHAR(64),
    size_bytes      INTEGER,
    content_type    VARCHAR(127),
    status          VARCHAR(16) NOT NULL DEFAULT 'ok',
    error           TEXT,
    secret_count    INTEGER NOT NULL DEFAULT 0,
    endpoint_count  INTEGER NOT NULL DEFAULT 0,
    endpoints       JSON,
    fetched_at      TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT uq_js_file_project_url UNIQUE (project_id, url)
);
CREATE INDEX ix_js_files_project_id ON js_files (project_id);
CREATE INDEX ix_js_files_host_id ON js_files (host_id);

CREATE TABLE js_secrets (
    id             SERIAL PRIMARY KEY,
    js_file_id     INTEGER NOT NULL REFERENCES js_files(id) ON DELETE CASCADE,
    kind           VARCHAR(64) NOT NULL,
    match_preview  VARCHAR(255) NOT NULL,
    snippet        TEXT,
    severity       VARCHAR(16) NOT NULL DEFAULT 'medium',
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_js_secrets_js_file_id ON js_secrets (js_file_id);

-- ---------------------------------------------------------------------------
-- vulnerabilities (+ assets)
-- ---------------------------------------------------------------------------
CREATE TABLE vulnerabilities (
    id                  SERIAL PRIMARY KEY,
    project_id          INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title               VARCHAR(500) NOT NULL,
    description         TEXT,
    severity            vuln_severity NOT NULL DEFAULT 'INFO',
    cvss_version        cvss_version,
    cvss_score          NUMERIC(4, 1),
    cvss_vector         VARCHAR(255),
    cwe_id              VARCHAR(20),
    status              vuln_status NOT NULL,
    workflow_steps      JSON,
    steps_to_reproduce  TEXT,
    impact              TEXT,
    recommendations     TEXT,
    created_by          INTEGER NOT NULL REFERENCES users(id),
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_vulnerabilities_project_id ON vulnerabilities (project_id);
CREATE INDEX ix_vulnerabilities_status ON vulnerabilities (status);

CREATE TABLE vulnerability_assets (
    id                SERIAL PRIMARY KEY,
    vulnerability_id  INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    asset_type        asset_type NOT NULL,
    asset_id          INTEGER NOT NULL,
    CONSTRAINT uq_vuln_asset UNIQUE (vulnerability_id, asset_type, asset_id)
);

-- ---------------------------------------------------------------------------
-- files
-- ---------------------------------------------------------------------------
CREATE TABLE files (
    id                SERIAL PRIMARY KEY,
    vulnerability_id  INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    original_name     VARCHAR(500) NOT NULL,
    content_type      VARCHAR(127) NOT NULL,
    size_bytes        BIGINT NOT NULL,
    minio_bucket      VARCHAR(63) NOT NULL,
    minio_key         TEXT NOT NULL,
    uploaded_by       INTEGER NOT NULL REFERENCES users(id),
    uploaded_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT ck_file_max_size CHECK (size_bytes <= 52428800)
);
CREATE INDEX ix_files_vulnerability_id ON files (vulnerability_id);

-- ---------------------------------------------------------------------------
-- comments (+ mentions)
-- ---------------------------------------------------------------------------
CREATE TABLE comments (
    id                SERIAL PRIMARY KEY,
    vulnerability_id  INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    user_id           INTEGER NOT NULL REFERENCES users(id),
    content           TEXT NOT NULL,
    created_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_comments_vulnerability_id ON comments (vulnerability_id);

CREATE TABLE comment_mentions (
    id          SERIAL PRIMARY KEY,
    comment_id  INTEGER NOT NULL REFERENCES comments(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT uq_comment_mention UNIQUE (comment_id, user_id)
);

-- ---------------------------------------------------------------------------
-- notifications
-- ---------------------------------------------------------------------------
CREATE TABLE notifications (
    id               SERIAL PRIMARY KEY,
    user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type             notification_type NOT NULL,
    comment_id       INTEGER REFERENCES comments(id) ON DELETE SET NULL,
    note_comment_id  INTEGER REFERENCES project_note_comments(id) ON DELETE SET NULL,
    project_id       INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    actor_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    status           VARCHAR(50),
    is_read          BOOLEAN NOT NULL DEFAULT false,
    created_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_notifications_user_id ON notifications (user_id);
CREATE INDEX ix_notifications_is_read ON notifications (is_read);

-- ---------------------------------------------------------------------------
-- audit_logs
-- ---------------------------------------------------------------------------
CREATE TABLE audit_logs (
    id           SERIAL PRIMARY KEY,
    user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action       VARCHAR(100) NOT NULL,
    entity_type  VARCHAR(50),
    entity_id    INTEGER,
    details      JSON,
    ip_address   VARCHAR(45),
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);
CREATE INDEX ix_audit_logs_user_id ON audit_logs (user_id);
CREATE INDEX ix_audit_logs_entity_type ON audit_logs (entity_type);
CREATE INDEX ix_audit_logs_entity_id ON audit_logs (entity_id);
CREATE INDEX ix_audit_logs_created_at ON audit_logs (created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS comment_mentions;
DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS vulnerability_assets;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS js_secrets;
DROP TABLE IF EXISTS js_files;
DROP TABLE IF EXISTS endpoints;
DROP TABLE IF EXISTS host_farm_jobs;
DROP TABLE IF EXISTS project_hidden_ips;
DROP TABLE IF EXISTS services;
DROP TABLE IF EXISTS ports;
DROP TABLE IF EXISTS host_ip_addresses;
DROP TABLE IF EXISTS hosts;
DROP TABLE IF EXISTS project_credentials;
DROP TABLE IF EXISTS project_note_comments;
DROP TABLE IF EXISTS project_notes;
DROP TABLE IF EXISTS project_members;
DROP TABLE IF EXISTS project_folders;
DROP TABLE IF EXISTS account_reactivation_tokens;
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS invitations;
DROP TABLE IF EXISTS mail_jobs;
DROP TABLE IF EXISTS agent_api_token_project_grants;
DROP TABLE IF EXISTS agent_api_tokens;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS users;

DROP TYPE IF EXISTS notification_type;
DROP TYPE IF EXISTS asset_type;
DROP TYPE IF EXISTS vuln_status;
DROP TYPE IF EXISTS cvss_version;
DROP TYPE IF EXISTS vuln_severity;
DROP TYPE IF EXISTS http_method;
DROP TYPE IF EXISTS port_state;
DROP TYPE IF EXISTS port_protocol;
DROP TYPE IF EXISTS host_os_type;
DROP TYPE IF EXISTS host_status;
DROP TYPE IF EXISTS project_status;
DROP TYPE IF EXISTS project_role;
DROP TYPE IF EXISTS user_role;
-- +goose StatementEnd

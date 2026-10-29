-- +goose Up
-- +goose StatementBegin

CREATE TABLE users (
    id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username             TEXT        NOT NULL CHECK (username ~ '^[A-Za-z0-9._-]{3,64}$'),
    password_hash        TEXT        NOT NULL,
    role                 TEXT        NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
    can_run_dast         BOOLEAN     NOT NULL DEFAULT false,
    is_active            BOOLEAN     NOT NULL DEFAULT true,
    must_change_password BOOLEAN     NOT NULL DEFAULT false,
    failed_attempts      INTEGER     NOT NULL DEFAULT 0,
    locked_until         TIMESTAMPTZ NULL,
    last_login_at        TIMESTAMPTZ NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_users_username ON users (lower(username));

CREATE TABLE projects (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        TEXT        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    description TEXT        NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_projects_name ON projects (lower(name));

CREATE TABLE ingest_tokens (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name         TEXT        NOT NULL,
    token_hash   TEXT        NOT NULL UNIQUE,
    token_prefix TEXT        NOT NULL,
    project_id   BIGINT      NULL REFERENCES projects (id) ON DELETE CASCADE,
    created_by   BIGINT      NULL REFERENCES users (id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NULL,
    revoked_at   TIMESTAMPTZ NULL
);

CREATE TABLE codebases (
    id                     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id             BIGINT      NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name                   TEXT        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    target_type            TEXT        NOT NULL CHECK (target_type IN ('repo', 'url')),
    language               TEXT        NOT NULL DEFAULT '',
    repo_url               TEXT        NULL,
    branch                 TEXT        NULL,
    subdirectory           TEXT        NOT NULL DEFAULT '',
    git_auth_kind          TEXT        NOT NULL DEFAULT 'none' CHECK (git_auth_kind IN ('none', 'https_token', 'ssh_key')),
    git_username           TEXT        NULL,
    git_secret_enc         BYTEA       NULL,
    base_url               TEXT        NULL,
    dast_status            TEXT        NULL CHECK (dast_status IN ('pending_confirmation', 'confirmed')),
    dast_registered_by     BIGINT      NULL REFERENCES users (id) ON DELETE RESTRICT,
    dast_confirmed_by      BIGINT      NULL REFERENCES users (id) ON DELETE RESTRICT,
    dast_confirmed_at      TIMESTAMPTZ NULL,
    dast_confirmation_text TEXT        NULL,
    dast_max_rps           INTEGER     NOT NULL DEFAULT 5 CHECK (dast_max_rps BETWEEN 1 AND 100),
    schedule_cron          TEXT        NULL,
    latest_scan_id         BIGINT      NULL,
    base_scan_id           BIGINT      NULL,
    n_critical             INTEGER     NOT NULL DEFAULT 0,
    n_high                 INTEGER     NOT NULL DEFAULT 0,
    n_medium               INTEGER     NOT NULL DEFAULT 0,
    n_low                  INTEGER     NOT NULL DEFAULT 0,
    n_info                 INTEGER     NOT NULL DEFAULT 0,
    n_low_confidence       INTEGER     NOT NULL DEFAULT 0,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT codebases_target_shape CHECK (
        (target_type = 'repo' AND repo_url IS NOT NULL AND base_url IS NULL AND dast_status IS NULL)
     OR (target_type = 'url'  AND base_url IS NOT NULL AND repo_url IS NULL AND dast_status IS NOT NULL)
    ),
    CONSTRAINT codebases_dast_trail CHECK (
        (dast_status = 'confirmed'
            AND dast_confirmed_by IS NOT NULL AND dast_confirmed_at IS NOT NULL AND dast_confirmation_text IS NOT NULL)
     OR (dast_status = 'pending_confirmation'
            AND dast_confirmed_by IS NULL AND dast_confirmed_at IS NULL AND dast_confirmation_text IS NULL)
     OR dast_status IS NULL
    )
);
CREATE UNIQUE INDEX uq_codebases_name ON codebases (project_id, lower(name));

CREATE TABLE scans (
    id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    codebase_id          BIGINT      NOT NULL REFERENCES codebases (id) ON DELETE CASCADE,
    type                 TEXT        NOT NULL CHECK (type IN ('sast', 'dast')),
    coverage             TEXT        NOT NULL DEFAULT 'full' CHECK (coverage IN ('full', 'partial')),
    trigger              TEXT        NOT NULL CHECK (trigger IN ('manual', 'schedule', 'ci')),
    status               TEXT        NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
    requested_by         BIGINT      NULL REFERENCES users (id) ON DELETE SET NULL,
    ingest_token_id      BIGINT      NULL REFERENCES ingest_tokens (id) ON DELETE SET NULL,
    queued_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at           TIMESTAMPTZ NULL,
    finished_at          TIMESTAMPTZ NULL,
    engine               TEXT        NULL,
    engine_version       TEXT        NULL,
    ref                  TEXT        NOT NULL DEFAULT '',
    scanned_file_count   INTEGER     NULL,
    n_critical           INTEGER     NOT NULL DEFAULT 0,
    n_high               INTEGER     NOT NULL DEFAULT 0,
    n_medium             INTEGER     NOT NULL DEFAULT 0,
    n_low                INTEGER     NOT NULL DEFAULT 0,
    n_info               INTEGER     NOT NULL DEFAULT 0,
    n_low_confidence     INTEGER     NOT NULL DEFAULT 0,
    duplicate_of_scan_id BIGINT      NULL REFERENCES scans (id) ON DELETE SET NULL,
    cancel_requested     BOOLEAN     NOT NULL DEFAULT false,
    worker_id            TEXT        NULL,
    lease_expires_at     TIMESTAMPTZ NULL,
    job_params           JSONB       NOT NULL DEFAULT '{}',
    error_code           TEXT        NULL,
    log_tail             TEXT        NULL,
    CONSTRAINT scans_id_codebase UNIQUE (id, codebase_id),
    CONSTRAINT scans_partial_only_ci CHECK (coverage = 'full' OR (trigger = 'ci' AND type = 'sast'))
);
CREATE INDEX ix_scans_queue ON scans (queued_at) WHERE status = 'queued';
CREATE UNIQUE INDEX uq_scans_active ON scans (codebase_id)
    WHERE status IN ('queued', 'running') AND trigger <> 'ci';
CREATE INDEX ix_scans_codebase ON scans (codebase_id, started_at DESC, id DESC);

ALTER TABLE codebases
    ADD CONSTRAINT codebases_latest_scan_fk FOREIGN KEY (latest_scan_id) REFERENCES scans (id) ON DELETE SET NULL,
    ADD CONSTRAINT codebases_base_scan_fk   FOREIGN KEY (base_scan_id)   REFERENCES scans (id) ON DELETE SET NULL;

CREATE TABLE scan_files (
    scan_id BIGINT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    path    TEXT   NOT NULL,
    PRIMARY KEY (scan_id, path)
);

CREATE TABLE findings (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id      BIGINT   NOT NULL,
    codebase_id  BIGINT   NOT NULL,
    is_current   BOOLEAN  NOT NULL DEFAULT false,
    rule_id      TEXT     NOT NULL,
    severity     TEXT     NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    severity_rank SMALLINT NOT NULL,
    confidence   TEXT     NOT NULL DEFAULT 'normal' CHECK (confidence IN ('normal', 'low')),
    message      TEXT     NOT NULL,
    location_kind TEXT    NOT NULL CHECK (location_kind IN ('file', 'url')),
    path         TEXT     NULL,
    url          TEXT     NULL,
    start_line   INTEGER  NULL,
    start_column INTEGER  NULL,
    end_line     INTEGER  NULL,
    end_column   INTEGER  NULL,
    snippet      TEXT     NOT NULL DEFAULT '',
    redacted     BOOLEAN  NOT NULL DEFAULT false,
    fingerprint  TEXT     NOT NULL,
    occurrence   INTEGER  NOT NULL DEFAULT 1,
    cwe          TEXT[]   NOT NULL DEFAULT '{}',
    CONSTRAINT findings_scan_fk FOREIGN KEY (scan_id, codebase_id)
        REFERENCES scans (id, codebase_id) ON DELETE CASCADE,
    CONSTRAINT findings_location CHECK (
        (location_kind = 'file' AND path IS NOT NULL) OR (location_kind = 'url' AND url IS NOT NULL)
    ),
    CONSTRAINT findings_rank CHECK (
        (severity = 'info' AND severity_rank = 0) OR (severity = 'low' AND severity_rank = 1)
     OR (severity = 'medium' AND severity_rank = 2) OR (severity = 'high' AND severity_rank = 3)
     OR (severity = 'critical' AND severity_rank = 4)
    )
);
CREATE UNIQUE INDEX uq_findings_identity ON findings (scan_id, fingerprint, occurrence);
CREATE INDEX ix_findings_cur_list ON findings (codebase_id, severity_rank DESC, path, start_line) WHERE is_current;
CREATE INDEX ix_findings_cur_path ON findings (codebase_id, path) WHERE is_current;
CREATE INDEX ix_findings_cur_rule ON findings (codebase_id, rule_id) WHERE is_current;
CREATE INDEX ix_findings_scan_list ON findings (scan_id, severity_rank DESC, path, start_line);
CREATE INDEX ix_findings_scan_path ON findings (scan_id, path);

CREATE TABLE ingest_digest (
    codebase_id  BIGINT      NOT NULL REFERENCES codebases (id) ON DELETE CASCADE,
    sarif_sha256 TEXT        NOT NULL CHECK (sarif_sha256 ~ '^[0-9a-f]{64}$'),
    ref          TEXT        NOT NULL DEFAULT '',
    scan_id      BIGINT      NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (codebase_id, sarif_sha256, ref)
);

CREATE TABLE sessions (
    id_hash      TEXT        PRIMARY KEY,
    user_id      BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token   TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX ix_sessions_user ON sessions (user_id);
CREATE INDEX ix_sessions_expiry ON sessions (expires_at);

CREATE TABLE audit_log (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_user_id BIGINT      NULL REFERENCES users (id) ON DELETE SET NULL,
    actor_name    TEXT        NOT NULL DEFAULT '',
    action        TEXT        NOT NULL,
    target        TEXT        NOT NULL DEFAULT ''
);
CREATE INDEX ix_audit_at ON audit_log (at DESC, id DESC);

-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS audit_log, sessions, ingest_digest, findings, scan_files CASCADE;
ALTER TABLE IF EXISTS codebases DROP CONSTRAINT IF EXISTS codebases_latest_scan_fk, DROP CONSTRAINT IF EXISTS codebases_base_scan_fk;
DROP TABLE IF EXISTS scans, codebases, ingest_tokens, projects, users CASCADE;

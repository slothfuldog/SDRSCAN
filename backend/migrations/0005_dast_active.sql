-- +goose Up
-- +goose StatementBegin

-- Active DAST scanning authorization: a SEPARATE, stricter layer on top of the basic DAST target
-- confirmation (dast_status = 'confirmed'). Active scanning sends test payloads (SQL injection,
-- reflected XSS, open redirect, header injection) to parameters found on the target, which can have
-- side effects on an application that mutates data via GET. Without this authorization a DAST scan
-- always stays passive (read-only checks), whatever is requested.
--
--  dast_active_authorized_at    when active scanning was authorized (NULL = not authorized).
--  dast_active_authorized_by    the user who authorized it.
--  dast_active_statement        the statement the user accepted, typed back with the codebase name
--                                (kept for audit; not a secret).
ALTER TABLE codebases
    ADD COLUMN IF NOT EXISTS dast_active_authorized_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS dast_active_authorized_by INTEGER     NULL REFERENCES users(id),
    ADD COLUMN IF NOT EXISTS dast_active_statement      TEXT        NULL;

ALTER TABLE codebases
    ADD CONSTRAINT codebases_dast_active_shape CHECK (
        (dast_active_authorized_at IS NULL AND dast_active_authorized_by IS NULL AND dast_active_statement IS NULL)
     OR (dast_active_authorized_at IS NOT NULL AND dast_active_authorized_by IS NOT NULL AND dast_active_statement IS NOT NULL
            AND target_type = 'url')
    );

-- Per-scan record of whether active scanning (and the time-based SQLi extra) was used, so the history
-- and audit trail show it and a re-run or schedule never silently inherits it.
ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS active         BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS active_timing  BOOLEAN NOT NULL DEFAULT false;

-- +goose StatementEnd

-- +goose Down
ALTER TABLE scans
    DROP COLUMN IF EXISTS active_timing, DROP COLUMN IF EXISTS active;

ALTER TABLE codebases
    DROP CONSTRAINT IF EXISTS codebases_dast_active_shape,
    DROP COLUMN IF EXISTS dast_active_statement, DROP COLUMN IF EXISTS dast_active_authorized_by, DROP COLUMN IF EXISTS dast_active_authorized_at;

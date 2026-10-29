-- +goose Up
-- +goose StatementBegin

-- Authenticated DAST and passive crawling, configured per URL target.
--
--  dast_auth_enc   the complete configuration INCLUDING secrets (passwords, tokens, header and cookie
--                  values) as one JSON document, sealed with AES-256-GCM (SDRSCAN_SECRET_KEY) like the
--                  git credentials. It is never returned by the API.
--  dast_auth_meta  the non-secret part for display (login URL, field names, username, header names ...).
--  dast_crawl_*    limits of the passive crawl (GET only, same origin).
ALTER TABLE codebases
    ADD COLUMN IF NOT EXISTS dast_auth_type       TEXT    NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS dast_auth_enc        BYTEA   NULL,
    ADD COLUMN IF NOT EXISTS dast_auth_meta       JSONB   NULL,
    ADD COLUMN IF NOT EXISTS dast_crawl_enabled   BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS dast_crawl_max_depth INTEGER NOT NULL DEFAULT 3,
    ADD COLUMN IF NOT EXISTS dast_crawl_max_pages INTEGER NOT NULL DEFAULT 50,
    ADD COLUMN IF NOT EXISTS dast_crawl_exclude   TEXT[]  NOT NULL DEFAULT '{}';

ALTER TABLE codebases
    ADD CONSTRAINT codebases_dast_auth_type  CHECK (dast_auth_type IN ('none', 'form', 'header', 'form+header')),
    ADD CONSTRAINT codebases_dast_auth_shape CHECK (
        (dast_auth_type = 'none' AND dast_auth_enc IS NULL AND dast_auth_meta IS NULL)
     OR (dast_auth_type <> 'none' AND target_type = 'url' AND dast_auth_enc IS NOT NULL
            AND dast_auth_meta IS NOT NULL AND jsonb_typeof(dast_auth_meta) = 'object')
    ),
    ADD CONSTRAINT codebases_dast_crawl_depth   CHECK (dast_crawl_max_depth BETWEEN 1 AND 10),
    ADD CONSTRAINT codebases_dast_crawl_pages   CHECK (dast_crawl_max_pages BETWEEN 1 AND 500),
    -- at most 20 patterns of at most 200 characters each (the joined text is at most 20*200 + 19 separators)
    ADD CONSTRAINT codebases_dast_crawl_exclude CHECK (
        cardinality(dast_crawl_exclude) <= 20
        AND char_length(array_to_string(dast_crawl_exclude, E'\n')) <= 4019
    ),
    ADD CONSTRAINT codebases_dast_crawl_target  CHECK (target_type = 'url' OR dast_crawl_enabled = false);

-- +goose StatementEnd

-- +goose Down
ALTER TABLE codebases
    DROP CONSTRAINT IF EXISTS codebases_dast_crawl_target,
    DROP CONSTRAINT IF EXISTS codebases_dast_crawl_exclude,
    DROP CONSTRAINT IF EXISTS codebases_dast_crawl_pages,
    DROP CONSTRAINT IF EXISTS codebases_dast_crawl_depth,
    DROP CONSTRAINT IF EXISTS codebases_dast_auth_shape,
    DROP CONSTRAINT IF EXISTS codebases_dast_auth_type,
    DROP COLUMN IF EXISTS dast_crawl_exclude, DROP COLUMN IF EXISTS dast_crawl_max_pages,
    DROP COLUMN IF EXISTS dast_crawl_max_depth, DROP COLUMN IF EXISTS dast_crawl_enabled,
    DROP COLUMN IF EXISTS dast_auth_meta, DROP COLUMN IF EXISTS dast_auth_enc, DROP COLUMN IF EXISTS dast_auth_type;

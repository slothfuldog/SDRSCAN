-- +goose Up
-- +goose StatementBegin

-- Optional OpenAPI/Swagger spec location for a URL target. When set, active scanning also exercises
-- the API operations the spec describes (GET/POST/PUT/PATCH; DELETE is never tested), in addition to
-- whatever the crawler finds and auto-discovers on its own. Null = auto-discovery only.
ALTER TABLE codebases
    ADD COLUMN IF NOT EXISTS dast_openapi_spec_url TEXT NULL;

ALTER TABLE codebases
    ADD CONSTRAINT codebases_dast_openapi_target CHECK (dast_openapi_spec_url IS NULL OR target_type = 'url');

-- +goose StatementEnd

-- +goose Down
ALTER TABLE codebases
    DROP CONSTRAINT IF EXISTS codebases_dast_openapi_target,
    DROP COLUMN IF EXISTS dast_openapi_spec_url;

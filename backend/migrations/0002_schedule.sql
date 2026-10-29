-- +goose Up
-- +goose StatementBegin

-- Scheduling (v2): one schedule per codebase, owned by the user who last set or
-- resumed it. A schedule is suspended (not deleted) when its owner is
-- deactivated or loses permission; it is re-activated with one step by an
-- entitled user.
UPDATE codebases SET schedule_cron = NULL WHERE schedule_cron IS NOT NULL;  -- ownerless schedules from before this migration are dropped

ALTER TABLE codebases DROP CONSTRAINT IF EXISTS codebases_schedule_shape;
ALTER TABLE codebases
    ADD COLUMN IF NOT EXISTS schedule_owner_id         BIGINT      NULL REFERENCES users (id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS schedule_status           TEXT        NULL CHECK (schedule_status IN ('active', 'suspended')),
    ADD COLUMN IF NOT EXISTS schedule_suspended_reason TEXT        NULL CHECK (schedule_suspended_reason IN ('owner_deactivated', 'owner_lost_permission')),
    ADD COLUMN IF NOT EXISTS schedule_suspended_at     TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS schedule_last_enqueued_at TIMESTAMPTZ NULL,
    ADD CONSTRAINT codebases_schedule_shape CHECK (
        (schedule_cron IS NULL AND schedule_owner_id IS NULL AND schedule_status IS NULL
            AND schedule_suspended_reason IS NULL AND schedule_suspended_at IS NULL AND schedule_last_enqueued_at IS NULL)
     OR (schedule_cron IS NOT NULL AND schedule_owner_id IS NOT NULL AND schedule_status IS NOT NULL
            AND ((schedule_status = 'suspended' AND schedule_suspended_reason IS NOT NULL AND schedule_suspended_at IS NOT NULL)
              OR (schedule_status = 'active' AND schedule_suspended_reason IS NULL AND schedule_suspended_at IS NULL)))
    );
CREATE INDEX IF NOT EXISTS ix_codebases_schedule ON codebases (schedule_status) WHERE schedule_cron IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
DROP INDEX IF EXISTS ix_codebases_schedule;
ALTER TABLE codebases
    DROP CONSTRAINT IF EXISTS codebases_schedule_shape,
    DROP COLUMN IF EXISTS schedule_last_enqueued_at, DROP COLUMN IF EXISTS schedule_suspended_at,
    DROP COLUMN IF EXISTS schedule_suspended_reason, DROP COLUMN IF EXISTS schedule_status, DROP COLUMN IF EXISTS schedule_owner_id;

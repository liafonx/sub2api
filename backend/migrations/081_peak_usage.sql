-- Add peak_usages table to track all-time peak resource usage for accounts and users.
CREATE TABLE IF NOT EXISTS peak_usages (
    id          BIGSERIAL PRIMARY KEY,
    entity_type VARCHAR(20) NOT NULL,
    entity_id   BIGINT NOT NULL,
    peak_concurrency INTEGER NOT NULL DEFAULT 0,
    peak_sessions    INTEGER NOT NULL DEFAULT 0,
    peak_rpm         INTEGER NOT NULL DEFAULT 0,
    reset_at    TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS peak_usages_entity_type_entity_id_key
    ON peak_usages (entity_type, entity_id);

-- Add scheduled_rate_config column to groups table
-- Stores an array of rate override rules for scheduled time windows
ALTER TABLE groups ADD COLUMN IF NOT EXISTS scheduled_rate_config JSONB DEFAULT NULL;

-- DOWN (rollback)
ALTER TABLE groups DROP COLUMN IF EXISTS scheduled_rate_config;

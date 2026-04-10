-- Add user_account_affinity_enabled to groups table (migration 082)
ALTER TABLE groups ADD COLUMN IF NOT EXISTS user_account_affinity_enabled boolean NOT NULL DEFAULT false;

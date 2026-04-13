-- Patch 23: Per-User RPM Cap
-- Adds rpm_limit column to users table. 0 = unlimited.
-- Default 35 is applied by application-level setting (default_rpm_limit),
-- not at the column level, so existing users remain unaffected.

ALTER TABLE users ADD COLUMN IF NOT EXISTS rpm_limit integer NOT NULL DEFAULT 0;

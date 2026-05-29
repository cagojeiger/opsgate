-- Restore Go-compatible request roles while preserving existing Rust data.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'viewer',
    ADD COLUMN IF NOT EXISTS deactivated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS anonymized_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS delete_after TIMESTAMPTZ;

UPDATE users
SET role = 'viewer'
WHERE role IS NULL OR role NOT IN ('admin', 'operator', 'viewer');

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_role_chk,
    ADD CONSTRAINT users_role_chk CHECK (role IN ('admin', 'operator', 'viewer'));

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_deactivated_after_created_chk,
    ADD CONSTRAINT users_deactivated_after_created_chk
        CHECK (deactivated_at IS NULL OR deactivated_at >= created_at),
    DROP CONSTRAINT IF EXISTS users_anonymized_after_deactivated_chk,
    ADD CONSTRAINT users_anonymized_after_deactivated_chk
        CHECK (anonymized_at IS NULL OR deactivated_at IS NOT NULL),
    DROP CONSTRAINT IF EXISTS users_delete_after_anonymized_chk,
    ADD CONSTRAINT users_delete_after_anonymized_chk
        CHECK (delete_after IS NULL OR anonymized_at IS NOT NULL);

ALTER TABLE audit_logs
    DROP CONSTRAINT IF EXISTS audit_logs_actor_role_chk;

UPDATE audit_logs
SET actor_role = 'viewer'
WHERE actor_role = 'active';

ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_actor_role_chk
        CHECK (actor_role IS NULL OR actor_role IN ('admin', 'operator', 'viewer'));

ALTER TABLE sql_query_history
    DROP CONSTRAINT IF EXISTS sql_query_history_actor_role_chk;

UPDATE sql_query_history
SET actor_role = 'viewer'
WHERE actor_role = 'active';

ALTER TABLE sql_query_history
    ADD CONSTRAINT sql_query_history_actor_role_chk
        CHECK (actor_role IS NULL OR actor_role IN ('admin', 'operator', 'viewer'));

ALTER TABLE api_call_history
    ADD COLUMN IF NOT EXISTS actor_role TEXT,
    ADD COLUMN IF NOT EXISTS request_id TEXT;

ALTER TABLE api_call_history
    DROP CONSTRAINT IF EXISTS api_call_history_actor_role_chk,
    ADD CONSTRAINT api_call_history_actor_role_chk
        CHECK (actor_role IS NULL OR actor_role IN ('admin', 'operator', 'viewer'));

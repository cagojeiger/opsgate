-- Add request metadata to credential lifecycle audit rows.
-- Existing rows are left nullable; new writes populate these from Caller.

ALTER TABLE credential_audit_events
    ADD COLUMN IF NOT EXISTS channel TEXT,
    ADD COLUMN IF NOT EXISTS actor_role TEXT,
    ADD COLUMN IF NOT EXISTS actor_ip TEXT,
    ADD COLUMN IF NOT EXISTS actor_user_agent TEXT,
    ADD COLUMN IF NOT EXISTS request_id TEXT;

ALTER TABLE credential_audit_events
    DROP CONSTRAINT IF EXISTS credential_audit_channel_chk,
    ADD CONSTRAINT credential_audit_channel_chk
        CHECK (channel IS NULL OR channel IN ('api', 'mcp', 'browser')),
    DROP CONSTRAINT IF EXISTS credential_audit_actor_role_chk,
    ADD CONSTRAINT credential_audit_actor_role_chk
        CHECK (actor_role IS NULL OR actor_role IN ('admin', 'operator', 'viewer'));

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsgate_app') THEN
        GRANT INSERT (
            channel, actor_role, actor_ip, actor_user_agent, request_id
        ) ON credential_audit_events TO opsgate_app;
    END IF;
END $$;

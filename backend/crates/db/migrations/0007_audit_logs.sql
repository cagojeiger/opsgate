-- Generic append-only audit log for tool/runtime activity.
-- Detail JSON must remain secret-free: no endpoint URLs, request/response bodies,
-- query/header values, SQL params, or secret material.

CREATE TABLE audit_logs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action           TEXT NOT NULL,
    channel          TEXT NOT NULL DEFAULT 'system',
    outcome          TEXT NOT NULL,
    severity         TEXT NOT NULL,
    actor_user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_role       TEXT,
    actor_ip         TEXT,
    actor_user_agent TEXT,
    target_type      TEXT,
    target_id        TEXT,
    target_key       TEXT,
    request_id       TEXT,
    purpose          TEXT,
    detail           JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT audit_logs_action_format_chk CHECK (action ~ '^[a-z][a-z0-9_.-]{1,126}$'),
    CONSTRAINT audit_logs_channel_chk CHECK (channel IN ('system', 'browser', 'api', 'mcp')),
    CONSTRAINT audit_logs_outcome_chk CHECK (outcome IN ('ok', 'denied', 'error')),
    CONSTRAINT audit_logs_severity_chk CHECK (severity IN ('info', 'warning', 'critical')),
    CONSTRAINT audit_logs_actor_role_chk CHECK (actor_role IS NULL OR actor_role IN ('active', 'admin')),
    CONSTRAINT audit_logs_target_type_chk CHECK (target_type IS NULL OR target_type ~ '^[a-z][a-z0-9_.-]{0,62}$'),
    CONSTRAINT audit_logs_purpose_chk CHECK (
        purpose IS NULL
        OR (length(purpose) BETWEEN 8 AND 512 AND position(chr(10) in purpose) = 0 AND position(chr(13) in purpose) = 0)
    ),
    CONSTRAINT audit_logs_detail_object_chk CHECK (jsonb_typeof(detail) = 'object')
);

CREATE INDEX audit_logs_created_at_idx
    ON audit_logs(created_at DESC, id DESC);

CREATE INDEX audit_logs_action_created_idx
    ON audit_logs(action, created_at DESC, id DESC);

CREATE INDEX audit_logs_actor_created_idx
    ON audit_logs(actor_user_id, created_at DESC, id DESC)
    WHERE actor_user_id IS NOT NULL;

CREATE INDEX audit_logs_target_created_idx
    ON audit_logs(target_type, target_key, created_at DESC, id DESC)
    WHERE target_type IS NOT NULL;

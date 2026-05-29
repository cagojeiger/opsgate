-- Secret-free credential lifecycle audit log.
-- Stores who changed a credential, what lifecycle action happened, and why.
-- Endpoint URLs, sealed ciphertext, and secret values must never be written here.

CREATE TABLE credential_audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    actor_user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   UUID NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    alias           TEXT NOT NULL,
    category        TEXT NOT NULL,
    action          TEXT NOT NULL,
    reason          TEXT,
    changed_fields  TEXT[] NOT NULL DEFAULT '{}',
    detail          JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT credential_audit_category_check CHECK (category IN ('http', 'sql')),
    CONSTRAINT credential_audit_action_check CHECK (action IN ('register', 'update', 'delete')),
    CONSTRAINT credential_audit_reason_no_crlf CHECK (
        reason IS NULL
        OR (position(chr(10) in reason) = 0 AND position(chr(13) in reason) = 0)
    )
);

CREATE INDEX credential_audit_owner_created_idx
    ON credential_audit_events(owner_user_id, created_at DESC, id DESC);

CREATE INDEX credential_audit_credential_created_idx
    ON credential_audit_events(credential_id, created_at DESC, id DESC);

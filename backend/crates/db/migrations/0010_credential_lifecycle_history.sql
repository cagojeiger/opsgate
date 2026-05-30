-- Versioned credential lifecycle history.

CREATE TABLE credential_history (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id       UUID REFERENCES credentials(id),
    owner_user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    alias               TEXT NOT NULL,
    action              TEXT NOT NULL,
    actor_user_id       UUID NOT NULL REFERENCES users(id),
    version             BIGINT NOT NULL,
    detail              JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT credential_history_action_chk CHECK (action IN ('register', 'update', 'delete')),
    CONSTRAINT credential_history_detail_object_chk CHECK (jsonb_typeof(detail) = 'object')
);

CREATE INDEX credential_history_owner_alias_idx
    ON credential_history(owner_user_id, alias, created_at DESC);

CREATE UNIQUE INDEX credential_history_owner_alias_version_uidx
    ON credential_history(owner_user_id, alias, version);

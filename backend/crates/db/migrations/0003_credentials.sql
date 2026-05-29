-- Credential catalog scoped to the authenticated user.
-- Secrets are stored only as ciphertext; list/read outputs must never expose them.

CREATE TABLE credentials (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category              TEXT NOT NULL,
    provider              TEXT NOT NULL,
    alias                 TEXT NOT NULL,
    endpoint              TEXT NOT NULL,
    secret_ciphertext     BYTEA NOT NULL,
    description           TEXT NOT NULL DEFAULT '',
    env                   TEXT NOT NULL DEFAULT 'dev',
    tags                  TEXT[] NOT NULL DEFAULT '{}',
    policy                JSONB NOT NULL DEFAULT '{}',
    allow_private_network BOOLEAN NOT NULL DEFAULT false,
    tls_ca                BYTEA,
    deleted_at            TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT credentials_category_check CHECK (category IN ('http', 'sql'))
);

CREATE UNIQUE INDEX credentials_owner_alias_active_key
    ON credentials(owner_user_id, alias)
    WHERE deleted_at IS NULL;

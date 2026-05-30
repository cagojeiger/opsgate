-- Credential catalog scoped to the authenticated user.
-- Secrets are stored only as ciphertext while active; delete cryptoshreds them.

CREATE TABLE credentials (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category              TEXT NOT NULL,
    provider              TEXT NOT NULL,
    alias                 TEXT NOT NULL,
    endpoint              TEXT NOT NULL,
    secret_ciphertext     BYTEA,
    description           TEXT NOT NULL DEFAULT '',
    env                   TEXT NOT NULL DEFAULT 'dev',
    tags                  TEXT[] NOT NULL DEFAULT '{}',
    policy                JSONB NOT NULL DEFAULT '{}',
    allow_private_network BOOLEAN NOT NULL DEFAULT false,
    tls_ca                BYTEA,
    created_by            UUID NOT NULL REFERENCES users(id),
    updated_by            UUID NOT NULL REFERENCES users(id),
    deleted_by            UUID REFERENCES users(id),
    deleted_at            TIMESTAMPTZ,
    secret_destroyed_at   TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT credentials_category_check CHECK (category IN ('http', 'sql')),
    CONSTRAINT credentials_deleted_pair_chk CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL)
        OR (deleted_at IS NOT NULL AND deleted_by IS NOT NULL)
    ),
    CONSTRAINT credentials_secret_lifecycle_chk CHECK (
        (deleted_at IS NULL AND secret_ciphertext IS NOT NULL AND secret_destroyed_at IS NULL)
        OR (deleted_at IS NOT NULL AND secret_ciphertext IS NULL AND secret_destroyed_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX credentials_owner_alias_active_key
    ON credentials(owner_user_id, alias)
    WHERE deleted_at IS NULL;

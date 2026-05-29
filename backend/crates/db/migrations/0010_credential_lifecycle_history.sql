-- Restore Go-compatible credential actor columns and lifecycle history.

ALTER TABLE credentials
    ADD COLUMN IF NOT EXISTS created_by UUID,
    ADD COLUMN IF NOT EXISTS updated_by UUID,
    ADD COLUMN IF NOT EXISTS deleted_by UUID;

UPDATE credentials
SET created_by = owner_user_id
WHERE created_by IS NULL;

UPDATE credentials
SET updated_by = owner_user_id
WHERE updated_by IS NULL;

UPDATE credentials
SET deleted_by = owner_user_id
WHERE deleted_at IS NOT NULL
  AND deleted_by IS NULL;

UPDATE credentials
SET deleted_by = NULL
WHERE deleted_at IS NULL;

UPDATE credentials
SET secret_ciphertext = NULL,
    secret_destroyed_at = COALESCE(secret_destroyed_at, deleted_at, now())
WHERE deleted_at IS NOT NULL;

UPDATE credentials
SET secret_destroyed_at = NULL
WHERE deleted_at IS NULL;

ALTER TABLE credentials
    ALTER COLUMN created_by SET NOT NULL,
    ALTER COLUMN updated_by SET NOT NULL,
    DROP CONSTRAINT IF EXISTS credentials_created_by_fkey,
    ADD CONSTRAINT credentials_created_by_fkey FOREIGN KEY (created_by) REFERENCES users(id),
    DROP CONSTRAINT IF EXISTS credentials_updated_by_fkey,
    ADD CONSTRAINT credentials_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES users(id),
    DROP CONSTRAINT IF EXISTS credentials_deleted_by_fkey,
    ADD CONSTRAINT credentials_deleted_by_fkey FOREIGN KEY (deleted_by) REFERENCES users(id),
    DROP CONSTRAINT IF EXISTS credentials_deleted_pair_chk,
    ADD CONSTRAINT credentials_deleted_pair_chk CHECK (
        (deleted_at IS NULL AND deleted_by IS NULL)
        OR (deleted_at IS NOT NULL AND deleted_by IS NOT NULL)
    ),
    DROP CONSTRAINT IF EXISTS credentials_secret_lifecycle_chk,
    ADD CONSTRAINT credentials_secret_lifecycle_chk CHECK (
        (deleted_at IS NULL AND secret_ciphertext IS NOT NULL AND secret_destroyed_at IS NULL)
        OR (deleted_at IS NOT NULL AND secret_ciphertext IS NULL AND secret_destroyed_at IS NOT NULL)
    );

CREATE TABLE IF NOT EXISTS credential_history (
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

CREATE INDEX IF NOT EXISTS credential_history_owner_alias_idx
    ON credential_history(owner_user_id, alias, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS credential_history_owner_alias_version_uidx
    ON credential_history(owner_user_id, alias, version);

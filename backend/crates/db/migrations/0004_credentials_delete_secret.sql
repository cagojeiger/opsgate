-- Allow credential delete to cryptoshred the sealed secret while keeping
-- non-secret catalog metadata and audit/history references.

ALTER TABLE credentials
    ALTER COLUMN secret_ciphertext DROP NOT NULL,
    ADD COLUMN secret_destroyed_at TIMESTAMPTZ;

-- Add optional mutual-TLS client-certificate material to HTTP credentials.
-- client_cert holds the public PEM certificate chain. client_key holds the
-- master-key-sealed private key ciphertext and must never be exposed.

ALTER TABLE credentials
    ADD COLUMN client_cert BYTEA,
    ADD COLUMN client_key  BYTEA;

ALTER TABLE credentials
    ADD CONSTRAINT credentials_client_cert_http_only_chk
        CHECK (client_cert IS NULL OR category = 'http'),
    ADD CONSTRAINT credentials_client_cert_key_pair_chk
        CHECK ((client_cert IS NULL) = (client_key IS NULL));

GRANT INSERT (client_cert, client_key) ON credentials TO opsgate_app;

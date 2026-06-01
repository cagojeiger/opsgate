-- Allow runtime soft-delete to clear HTTP client-certificate material.
-- 0003 may already be applied, so this permission change lives in a new migration.

GRANT UPDATE (client_cert, client_key) ON credentials TO opsgate_app;

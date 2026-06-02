-- Create and grant the narrowed database role used by OPSGATE_RETENTION_DATABASE_URL.

DO $$
BEGIN
    CREATE ROLE opsgate_retention LOGIN PASSWORD 'opsgate_retention';
EXCEPTION
    WHEN duplicate_object OR unique_violation THEN
        NULL;
END $$;

DO $$
DECLARE
    schema_name text := current_schema();
BEGIN
    EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM opsgate_retention', schema_name);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO opsgate_retention', schema_name);
END $$;

GRANT SELECT, DELETE ON api_call_history TO opsgate_retention;
GRANT SELECT, DELETE ON sql_query_history TO opsgate_retention;
GRANT SELECT, DELETE ON audit_logs TO opsgate_retention;
GRANT SELECT, DELETE ON credential_history TO opsgate_retention;
GRANT SELECT, DELETE ON credentials TO opsgate_retention;

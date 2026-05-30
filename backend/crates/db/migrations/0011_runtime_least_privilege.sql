-- Create and grant the narrowed runtime database role used by OPSGATE_DATABASE_URL.

DO $$
BEGIN
    CREATE ROLE opsgate_app LOGIN PASSWORD 'opsgate_app';
EXCEPTION
    WHEN duplicate_object OR unique_violation THEN
        NULL;
END $$;

DO $$
DECLARE
    schema_name text := current_schema();
BEGIN
    EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM PUBLIC', schema_name);
    EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM opsgate_app', schema_name);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO opsgate_app', schema_name);
END $$;

GRANT SELECT ON users TO opsgate_app;
GRANT INSERT (sub, email, display_name) ON users TO opsgate_app;
GRANT UPDATE (display_name, updated_at) ON users TO opsgate_app;

GRANT SELECT ON credentials TO opsgate_app;
GRANT INSERT (
    owner_user_id, category, provider, alias, endpoint, secret_ciphertext,
    description, env, tags, policy, allow_private_network, tls_ca,
    created_by, updated_by
) ON credentials TO opsgate_app;
GRANT UPDATE (
    description, env, tags, policy,
    secret_ciphertext, secret_destroyed_at,
    deleted_at, deleted_by, updated_by, updated_at
) ON credentials TO opsgate_app;

GRANT SELECT ON credential_history TO opsgate_app;
GRANT INSERT (
    credential_id, owner_user_id, alias, action, actor_user_id, version, detail
) ON credential_history TO opsgate_app;

GRANT INSERT (
    owner_user_id, actor_user_id, actor_ip, actor_user_agent, request_id,
    channel, credential_id, alias, category, action, reason, changed_fields, detail
) ON credential_audit_events TO opsgate_app;

GRANT INSERT (
    owner_user_id, actor_user_id, channel, request_id,
    credential_id, credential_alias, credential_category, credential_provider,
    credential_env, method, path, query_keys, request_header_keys,
    projection_keys, max_bytes, purpose, outcome, status_code, latency_ms,
    original_bytes, returned_bytes, truncated, error_kind, error_message_safe
) ON api_call_history TO opsgate_app;

GRANT INSERT (
    owner_user_id, actor_user_id, channel, request_id,
    credential_id, credential_alias, credential_category, credential_provider,
    credential_env, query_sha256, params_count, shape, max_rows, max_bytes,
    timeout_ms, purpose, outcome, latency_ms, row_count, returned_bytes,
    truncated, result_columns, error_kind, error_message_safe
) ON sql_query_history TO opsgate_app;

GRANT INSERT (
    action, channel, outcome, severity, actor_user_id, actor_ip,
    actor_user_agent, target_type, target_id, target_key, request_id, purpose,
    detail
) ON audit_logs TO opsgate_app;

DO $$
DECLARE
    schema_name text := current_schema();
BEGIN
    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO opsgate_app', schema_name);
END $$;

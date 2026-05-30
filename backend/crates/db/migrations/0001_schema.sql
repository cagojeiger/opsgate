-- Current opsgate schema. Pre-production migrations are intentionally squashed.
-- Target URLs, secret ciphertext, request/response bodies, SQL text/params, and
-- secret material must never be written to history/audit detail JSON.

CREATE TABLE users (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sub          TEXT NOT NULL UNIQUE,
    email        TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    is_active    BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE credentials (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id              UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category                   TEXT NOT NULL,
    provider                   TEXT NOT NULL,
    alias                      TEXT NOT NULL,
    http_origin                TEXT,
    http_base_path             TEXT,
    sql_database_url           TEXT,
    secret_ciphertext          BYTEA,
    description                TEXT NOT NULL DEFAULT '',
    env                        TEXT NOT NULL DEFAULT 'dev',
    tags                       TEXT[] NOT NULL DEFAULT '{}',
    policy                     JSONB NOT NULL DEFAULT '{}',
    allow_private_network      BOOLEAN NOT NULL DEFAULT false,
    allow_insecure_transport   BOOLEAN NOT NULL DEFAULT false,
    tls_ca                     BYTEA,
    created_by                 UUID NOT NULL REFERENCES users(id),
    updated_by                 UUID NOT NULL REFERENCES users(id),
    deleted_by                 UUID REFERENCES users(id),
    deleted_at                 TIMESTAMPTZ,
    secret_destroyed_at        TIMESTAMPTZ,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT credentials_category_check CHECK (category IN ('http', 'sql')),
    CONSTRAINT credentials_target_by_category_chk CHECK (
        (
            category = 'http'
            AND http_origin IS NOT NULL
            AND http_base_path IS NOT NULL
            AND sql_database_url IS NULL
        )
        OR (
            category = 'sql'
            AND http_origin IS NULL
            AND http_base_path IS NULL
            AND sql_database_url IS NOT NULL
        )
    ),
    CONSTRAINT credentials_http_origin_nonempty_chk CHECK (
        http_origin IS NULL OR length(btrim(http_origin)) > 0
    ),
    CONSTRAINT credentials_http_base_path_chk CHECK (
        http_base_path IS NULL OR left(http_base_path, 1) = '/'
    ),
    CONSTRAINT credentials_sql_database_url_nonempty_chk CHECK (
        sql_database_url IS NULL OR length(btrim(sql_database_url)) > 0
    ),
    CONSTRAINT credentials_tls_ca_http_only_chk CHECK (tls_ca IS NULL OR category = 'http'),
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

CREATE TABLE credential_history (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id       UUID REFERENCES credentials(id),
    owner_user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    alias               TEXT NOT NULL,
    action              TEXT NOT NULL,
    actor_user_id       UUID NOT NULL REFERENCES users(id),
    actor_ip            TEXT,
    actor_user_agent    TEXT,
    request_id          TEXT,
    channel             TEXT,
    reason              TEXT,
    changed_fields      TEXT[] NOT NULL DEFAULT '{}',
    version             BIGINT NOT NULL,
    detail              JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT credential_history_action_chk CHECK (action IN ('register', 'update', 'delete')),
    CONSTRAINT credential_history_channel_chk CHECK (channel IS NULL OR channel IN ('api', 'mcp', 'browser')),
    CONSTRAINT credential_history_detail_object_chk CHECK (jsonb_typeof(detail) = 'object'),
    CONSTRAINT credential_history_reason_no_crlf CHECK (
        reason IS NULL
        OR (position(chr(10) in reason) = 0 AND position(chr(13) in reason) = 0)
    )
);

CREATE INDEX credential_history_owner_alias_idx
    ON credential_history(owner_user_id, alias, created_at DESC);

CREATE UNIQUE INDEX credential_history_owner_alias_version_uidx
    ON credential_history(owner_user_id, alias, version);

CREATE TABLE api_call_history (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id       UUID REFERENCES users(id) ON DELETE CASCADE,
    actor_user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    channel             TEXT NOT NULL DEFAULT 'mcp',
    request_id          TEXT,
    credential_id       UUID REFERENCES credentials(id) ON DELETE SET NULL,
    credential_alias    TEXT NOT NULL DEFAULT '',
    credential_category TEXT NOT NULL DEFAULT '',
    credential_provider TEXT NOT NULL DEFAULT '',
    credential_env      TEXT NOT NULL DEFAULT '',
    method              TEXT NOT NULL DEFAULT '',
    request_path        TEXT NOT NULL DEFAULT '',
    query_keys          JSONB NOT NULL DEFAULT '[]'::jsonb,
    request_header_keys JSONB NOT NULL DEFAULT '[]'::jsonb,
    projection_keys     JSONB NOT NULL DEFAULT '[]'::jsonb,
    max_bytes           INTEGER NOT NULL DEFAULT 0,
    purpose             TEXT,
    outcome             TEXT NOT NULL,
    status_code         INTEGER,
    latency_ms          BIGINT,
    original_bytes      INTEGER,
    returned_bytes      INTEGER,
    truncated           BOOLEAN NOT NULL DEFAULT FALSE,
    error_kind          TEXT,
    error_message_safe  TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT api_call_history_channel_chk CHECK (channel IN ('api', 'mcp')),
    CONSTRAINT api_call_history_method_chk CHECK (method = '' OR method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')),
    CONSTRAINT api_call_history_query_keys_array_chk CHECK (jsonb_typeof(query_keys) = 'array'),
    CONSTRAINT api_call_history_request_header_keys_array_chk CHECK (jsonb_typeof(request_header_keys) = 'array'),
    CONSTRAINT api_call_history_projection_keys_array_chk CHECK (jsonb_typeof(projection_keys) = 'array'),
    CONSTRAINT api_call_history_purpose_chk CHECK (
        purpose IS NULL
        OR (length(purpose) BETWEEN 8 AND 512 AND position(chr(10) in purpose) = 0 AND position(chr(13) in purpose) = 0)
    ),
    CONSTRAINT api_call_history_outcome_chk CHECK (outcome IN ('ok', 'denied', 'error')),
    CONSTRAINT api_call_history_status_code_chk CHECK (status_code IS NULL OR (status_code >= 100 AND status_code <= 599)),
    CONSTRAINT api_call_history_latency_chk CHECK (latency_ms IS NULL OR latency_ms >= 0),
    CONSTRAINT api_call_history_bytes_chk CHECK (
        (original_bytes IS NULL OR original_bytes >= 0)
        AND (returned_bytes IS NULL OR returned_bytes >= 0)
        AND max_bytes >= 0
    ),
    CONSTRAINT api_call_history_error_kind_chk CHECK (error_kind IS NULL OR error_kind ~ '^[a-z][a-z0-9_.-]{0,126}$')
);

CREATE INDEX api_call_history_owner_created_idx
    ON api_call_history(owner_user_id, created_at DESC, id DESC);

CREATE INDEX api_call_history_credential_created_idx
    ON api_call_history(credential_id, created_at DESC, id DESC);

CREATE TABLE sql_query_history (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id       UUID REFERENCES users(id) ON DELETE CASCADE,
    actor_user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    channel             TEXT NOT NULL DEFAULT 'mcp',
    request_id          TEXT,
    credential_id       UUID REFERENCES credentials(id) ON DELETE SET NULL,
    credential_alias    TEXT NOT NULL DEFAULT '',
    credential_category TEXT NOT NULL DEFAULT '',
    credential_provider TEXT NOT NULL DEFAULT '',
    credential_env      TEXT NOT NULL DEFAULT '',
    query_sha256        TEXT NOT NULL DEFAULT '',
    params_count        INTEGER NOT NULL DEFAULT 0,
    max_rows            INTEGER NOT NULL DEFAULT 0,
    max_bytes           INTEGER NOT NULL DEFAULT 0,
    timeout_ms          INTEGER NOT NULL DEFAULT 0,
    purpose             TEXT,
    outcome             TEXT NOT NULL,
    latency_ms          BIGINT,
    row_count           INTEGER,
    returned_bytes      INTEGER,
    truncated           BOOLEAN NOT NULL DEFAULT FALSE,
    result_columns      JSONB NOT NULL DEFAULT '[]'::jsonb,
    error_kind          TEXT,
    error_message_safe  TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT sql_query_history_channel_chk CHECK (channel IN ('api', 'mcp')),
    CONSTRAINT sql_query_history_query_sha256_chk CHECK (query_sha256 = '' OR query_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT sql_query_history_params_count_chk CHECK (params_count >= 0),
    CONSTRAINT sql_query_history_budget_chk CHECK (max_rows >= 0 AND max_bytes >= 0 AND timeout_ms >= 0),
    CONSTRAINT sql_query_history_purpose_chk CHECK (
        purpose IS NULL
        OR (length(purpose) BETWEEN 8 AND 512 AND position(chr(10) in purpose) = 0 AND position(chr(13) in purpose) = 0)
    ),
    CONSTRAINT sql_query_history_outcome_chk CHECK (outcome IN ('ok', 'denied', 'error')),
    CONSTRAINT sql_query_history_result_columns_array_chk CHECK (jsonb_typeof(result_columns) = 'array'),
    CONSTRAINT sql_query_history_counts_chk CHECK (
        (row_count IS NULL OR row_count >= 0)
        AND (returned_bytes IS NULL OR returned_bytes >= 0)
    ),
    CONSTRAINT sql_query_history_error_kind_chk CHECK (error_kind IS NULL OR error_kind ~ '^[a-z][a-z0-9_.-]{0,126}$')
);

CREATE INDEX sql_query_history_owner_created_idx
    ON sql_query_history(owner_user_id, created_at DESC, id DESC);

CREATE INDEX sql_query_history_credential_created_idx
    ON sql_query_history(credential_id, created_at DESC, id DESC);

CREATE TABLE audit_logs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action           TEXT NOT NULL,
    channel          TEXT NOT NULL DEFAULT 'system',
    outcome          TEXT NOT NULL,
    severity         TEXT NOT NULL,
    actor_user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_ip         TEXT,
    actor_user_agent TEXT,
    target_type      TEXT,
    target_id        TEXT,
    target_key       TEXT,
    request_id       TEXT,
    purpose          TEXT,
    detail           JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT audit_logs_action_format_chk CHECK (action ~ '^[a-z][a-z0-9_.-]{1,126}$'),
    CONSTRAINT audit_logs_channel_chk CHECK (channel IN ('system', 'browser', 'api', 'mcp')),
    CONSTRAINT audit_logs_outcome_chk CHECK (outcome IN ('ok', 'denied', 'error')),
    CONSTRAINT audit_logs_severity_chk CHECK (severity IN ('info', 'warning', 'critical')),
    CONSTRAINT audit_logs_target_type_chk CHECK (target_type IS NULL OR target_type ~ '^[a-z][a-z0-9_.-]{0,62}$'),
    CONSTRAINT audit_logs_purpose_chk CHECK (
        purpose IS NULL
        OR (length(purpose) BETWEEN 8 AND 512 AND position(chr(10) in purpose) = 0 AND position(chr(13) in purpose) = 0)
    ),
    CONSTRAINT audit_logs_detail_object_chk CHECK (jsonb_typeof(detail) = 'object')
);

CREATE INDEX audit_logs_created_at_idx
    ON audit_logs(created_at DESC, id DESC);

CREATE INDEX audit_logs_action_created_idx
    ON audit_logs(action, created_at DESC, id DESC);

CREATE INDEX audit_logs_actor_created_idx
    ON audit_logs(actor_user_id, created_at DESC, id DESC)
    WHERE actor_user_id IS NOT NULL;

CREATE INDEX audit_logs_target_created_idx
    ON audit_logs(target_type, target_key, created_at DESC, id DESC)
    WHERE target_type IS NOT NULL;

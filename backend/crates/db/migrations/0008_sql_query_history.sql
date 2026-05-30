-- sql.query execution facts for operational analysis.
-- Never stores endpoint URLs, query text, parameter values, result values, or secret material.

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

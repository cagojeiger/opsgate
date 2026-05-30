-- api.call execution facts for operational analysis.
-- Never stores endpoint URLs, request/response bodies, query/header values, or secret material.

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
    path                TEXT NOT NULL DEFAULT '',
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

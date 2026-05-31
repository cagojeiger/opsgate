use std::time::Instant;

use opsgate_core::llm_output::validate_json_paths;
use opsgate_core::validation::{trim_required, validate_purpose};
use opsgate_core::{Error, Result};
use opsgate_db::{AuditRepo, CredentialRepo, SqlQueryHistoryParams, SqlQueryHistoryRepo};
use opsgate_domain::Caller;
use opsgate_domain::credential::{Credential, CredentialCategory};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use sqlx::PgConnection;
use sqlx::types::Json;

use crate::audit::runtime::reason;
use crate::credential::snapshot::CredentialSnapshot;
use crate::sql_common::SqlSecret;

use super::output::{SqlQueryOutput, build_column_output};
use super::policy::{enforce_sql_policy, validate_policy_boundary};

const DEFAULT_MAX_ROWS: i32 = 100;
const MAX_MAX_ROWS: i32 = 1000;
const DEFAULT_MAX_BYTES: usize = 64 * 1024;
const MIN_MAX_BYTES: usize = 1024;
pub(super) const MAX_MAX_BYTES: usize = 1024 * 1024;
const DEFAULT_TIMEOUT_MS: u32 = 3000;
const MAX_TIMEOUT_MS: u32 = 30000;
const MAX_QUERY_LEN: usize = 16_000;
const MAX_PARAMS: usize = 64;
#[derive(Clone)]
pub(crate) struct SqlQueryService {
    credentials: CredentialRepo,
    history: SqlQueryHistoryRepo,
    audit: AuditRepo,
    sealer: opsgate_core::crypto::Sealer,
    pools: crate::target::pg_pool::TargetPgPools,
}

impl SqlQueryService {
    pub fn new(
        credentials: CredentialRepo,
        history: SqlQueryHistoryRepo,
        audit: AuditRepo,
        sealer: opsgate_core::crypto::Sealer,
        pools: crate::target::pg_pool::TargetPgPools,
    ) -> Self {
        Self {
            credentials,
            history,
            audit,
            sealer,
            pools,
        }
    }

    pub async fn execute(&self, caller: &Caller, input: SqlQueryInput) -> Result<SqlQueryOutput> {
        // Sanitize the raw alias up front: on the bad-input path it is the only
        // request field we record, and it has not been validated yet.
        let raw_alias = crate::audit::safe::message(&input.alias);
        let input = match normalize_input(input) {
            Ok(input) => input,
            Err(error) => {
                self.record_bad_input(caller, &raw_alias, &error).await;
                return Err(error);
            }
        };
        let mut recorder = QueryRecorder::new(&self.history, &self.audit, caller, &input);

        let row = match self
            .credentials
            .find_credential_secret_by_alias(caller.user.id, &input.alias)
            .await?
        {
            Some(row) => row,
            None => {
                recorder
                    .denied(reason::CREDENTIAL_NOT_FOUND, "credential not found")
                    .await;
                return Err(Error::not_found("credential not found"));
            }
        };
        let material = row.into_credential()?;
        let credential = material.credential;
        recorder.set_credential(&credential);

        if credential.category != CredentialCategory::Sql || credential.provider != "postgres" {
            recorder
                .denied(
                    reason::WRONG_CREDENTIAL_PROVIDER,
                    "credential is not sql/postgres",
                )
                .await;
            return Err(Error::validation(reason::WRONG_CREDENTIAL_PROVIDER));
        }
        if let Err(error) = validate_policy_boundary(&credential.policy, &input) {
            recorder
                .denied(reason::POLICY_DENIED, &error.to_string())
                .await;
            return Err(error);
        }
        if let Err(error) = enforce_sql_policy(&input.query, &credential.policy) {
            recorder
                .denied(reason::POLICY_DENIED, &error.to_string())
                .await;
            return Err(error);
        }
        let secret_ciphertext = match material.secret_ciphertext {
            Some(secret_ciphertext) => secret_ciphertext,
            None => {
                recorder
                    .err(reason::SECRET_DESTROYED, "credential secret is destroyed")
                    .await;
                return Err(Error::validation("credential secret is destroyed"));
            }
        };
        let secret = match crate::sql_common::open_sql_secret(
            &self.sealer,
            &credential.alias,
            &secret_ciphertext,
        ) {
            Ok(secret) => secret,
            Err(error) => {
                recorder
                    .err(reason::SECRET_OPEN_FAILED, "credential secret open failed")
                    .await;
                return Err(error);
            }
        };
        let target = match crate::target::postgres::prepare_postgres_target(
            crate::sql_common::credential_database_url(&credential)?,
            credential.allow_private_network,
            credential.allow_insecure_transport,
        )
        .await
        {
            Ok(target) => target,
            Err(error) => {
                recorder
                    .err(reason::TARGET_PREPARE_FAILED, "target prepare failed")
                    .await;
                return Err(error);
            }
        };

        let started = Instant::now();
        let mut output =
            match execute_postgres(&self.pools, credential.id, &target, &secret, &input).await {
                Ok(output) => output,
                Err(error) => {
                    recorder.err(reason::QUERY_FAILED, "sql query failed").await;
                    return Err(error);
                }
            };
        output.latency_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        recorder.ok(&output).await;
        Ok(output)
    }

    /// Record an input-validation rejection (before a normalized input exists).
    /// Mirrors the per-tool denial stream so input-shaped abuse is still audited.
    async fn record_bad_input(&self, caller: &Caller, alias: &str, error: &Error) {
        self.record_pre_input_denial(caller, alias, reason::BAD_INPUT, error)
            .await;
    }

    async fn record_pre_input_denial(
        &self,
        caller: &Caller,
        alias: &str,
        reason: &str,
        error: &Error,
    ) {
        crate::audit::append_event(
            &self.audit,
            pre_input_denial_audit_event(caller, alias, reason),
            "sql.query.audit_failed",
        )
        .await;
        if let Err(error) = self
            .history
            .insert(pre_input_denial_history_params(
                caller, alias, reason, error,
            ))
            .await
        {
            tracing::error!(event = "sql.query.history_failed", detail = %error);
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct SqlQueryInput {
    /// Alias from credential.list with category=sql and provider=postgres.
    pub alias: String,
    /// Short human reason for the query; stored in audit/history.
    pub purpose: String,
    /// Read-only SQL. Only SELECT/WITH are allowed. Prefer explicit columns, WHERE, count/group, or keyset pagination; avoid SELECT *.
    pub query: String,
    /// Positional bind parameters for the SQL query.
    #[serde(default)]
    #[schemars(schema_with = "opsgate_core::schema::json_value_array_schema")]
    pub params: Vec<Value>,
    /// 1-3 JSONPath projections to shrink the returned JSON after SQL execution.
    #[serde(default)]
    pub jsonpath: Vec<String>,
    /// Maximum rows to fetch before JSONPath/byte trimming. Prefer narrowing the SQL when possible.
    pub max_rows: Option<i32>,
    /// Response byte budget after SQL shaping and JSONPath projection.
    pub max_bytes: Option<usize>,
    /// Query timeout in milliseconds, bounded by credential policy.
    pub timeout_ms: Option<u32>,
}

#[derive(Debug, Clone)]
pub(super) struct NormalizedInput {
    pub(super) alias: String,
    pub(super) purpose: String,
    pub(super) query: String,
    pub(super) params: Vec<Value>,
    pub(super) jsonpath: Vec<String>,
    pub(super) max_rows: i32,
    pub(super) max_bytes: usize,
    pub(super) timeout_ms: u32,
    pub(super) query_sha256: String,
}

fn normalize_input(input: SqlQueryInput) -> Result<NormalizedInput> {
    let alias = trim_required("alias", &input.alias)?;
    let purpose = validate_purpose(&input.purpose)?;
    let query = input.query.trim().to_owned();
    if query.is_empty() || query.len() > MAX_QUERY_LEN || query.contains('\0') {
        return Err(Error::validation(format!(
            "query must be 1-{MAX_QUERY_LEN} characters without NUL"
        )));
    }
    if input.params.len() > MAX_PARAMS {
        return Err(Error::validation(format!(
            "too many params ({} > {MAX_PARAMS})",
            input.params.len()
        )));
    }
    validate_json_paths(&input.jsonpath)?;
    let max_rows = input.max_rows.unwrap_or(DEFAULT_MAX_ROWS);
    if !(1..=MAX_MAX_ROWS).contains(&max_rows) {
        return Err(Error::validation("max_rows out of range"));
    }
    let max_bytes = input.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    if !(MIN_MAX_BYTES..=MAX_MAX_BYTES).contains(&max_bytes) {
        return Err(Error::validation("max_bytes out of range"));
    }
    let timeout_ms = input.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(Error::validation("timeout_ms out of range"));
    }
    let query_sha256 = sha256_hex(&query);
    Ok(NormalizedInput {
        alias,
        purpose,
        query,
        params: input.params,
        jsonpath: input.jsonpath,
        max_rows,
        max_bytes,
        timeout_ms,
        query_sha256,
    })
}

async fn execute_postgres(
    pools: &crate::target::pg_pool::TargetPgPools,
    credential_id: uuid::Uuid,
    target: &crate::target::postgres::GuardedPostgresTarget,
    secret: &SqlSecret,
    input: &NormalizedInput,
) -> Result<SqlQueryOutput> {
    let mut conn = crate::sql_common::begin_read_only_connection(
        pools,
        credential_id,
        target,
        secret,
        input.timeout_ms,
    )
    .await?;
    let result = if input
        .query
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("explain")
    {
        load_explain_rows(&mut conn, input).await
    } else {
        load_rows(&mut conn, input).await
    };
    crate::sql_common::finish_read_only_result(&mut conn, result).await
}

async fn load_explain_rows(
    conn: &mut PgConnection,
    input: &NormalizedInput,
) -> Result<SqlQueryOutput> {
    let mut query = sqlx::query_scalar::<_, String>(&input.query);
    for param in &input.params {
        query = bind_string_param(query, param)?;
    }
    let mut plans = query
        .fetch_all(conn)
        .await
        .map_err(|_error| Error::internal("sql query failed"))?;
    let mut truncated = false;
    if plans.len() > usize::try_from(input.max_rows).unwrap_or(usize::MAX) {
        plans.truncate(usize::try_from(input.max_rows).unwrap_or(usize::MAX));
        truncated = true;
    }
    let rows = plans
        .into_iter()
        .map(|line| serde_json::json!({"QUERY PLAN": line}))
        .collect();
    build_column_output(rows, input, truncated)
}

async fn load_rows(conn: &mut PgConnection, input: &NormalizedInput) -> Result<SqlQueryOutput> {
    let limit = input.max_rows + 1;
    let wrapped = format!(
        "SELECT COALESCE(json_agg(row_to_json(opsgate_limited)), '[]'::json) AS rows FROM (SELECT * FROM ({}) AS opsgate_q LIMIT {}) AS opsgate_limited",
        input.query, limit
    );
    let mut query = sqlx::query_scalar::<_, Value>(&wrapped);
    for param in &input.params {
        query = bind_json_param(query, param)?;
    }
    let value = query
        .fetch_one(conn)
        .await
        .map_err(|_error| Error::internal("sql query failed"))?;
    // json_agg always yields an array; move it out instead of cloning the rows.
    let mut rows = match value {
        Value::Array(rows) => rows,
        _ => Vec::new(),
    };
    let mut truncated = false;
    if rows.len() > usize::try_from(input.max_rows).unwrap_or(usize::MAX) {
        rows.truncate(usize::try_from(input.max_rows).unwrap_or(usize::MAX));
        truncated = true;
    }
    build_column_output(rows, input, truncated)
}

fn bind_string_param<'q>(
    query: sqlx::query::QueryScalar<'q, sqlx::Postgres, String, sqlx::postgres::PgArguments>,
    value: &Value,
) -> Result<sqlx::query::QueryScalar<'q, sqlx::Postgres, String, sqlx::postgres::PgArguments>> {
    let query = match value {
        Value::Null => query.bind(Option::<String>::None),
        Value::Bool(value) => query.bind(*value),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                query.bind(value)
            } else if let Some(value) = number.as_u64() {
                let value = i64::try_from(value)
                    .map_err(|_error| Error::validation("numeric param out of range"))?;
                query.bind(value)
            } else if let Some(value) = number.as_f64() {
                query.bind(value)
            } else {
                return Err(Error::validation("invalid numeric param"));
            }
        }
        Value::String(value) => query.bind(value.clone()),
        Value::Array(_) | Value::Object(_) => query.bind(Json(value.clone())),
    };
    Ok(query)
}

fn bind_json_param<'q>(
    query: sqlx::query::QueryScalar<'q, sqlx::Postgres, Value, sqlx::postgres::PgArguments>,
    value: &Value,
) -> Result<sqlx::query::QueryScalar<'q, sqlx::Postgres, Value, sqlx::postgres::PgArguments>> {
    let query = match value {
        Value::Null => query.bind(Option::<String>::None),
        Value::Bool(value) => query.bind(*value),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                query.bind(value)
            } else if let Some(value) = number.as_u64() {
                let value = i64::try_from(value)
                    .map_err(|_error| Error::validation("numeric param out of range"))?;
                query.bind(value)
            } else if let Some(value) = number.as_f64() {
                query.bind(value)
            } else {
                return Err(Error::validation("invalid numeric param"));
            }
        }
        Value::String(value) => query.bind(value.clone()),
        Value::Array(_) | Value::Object(_) => query.bind(Json(value.clone())),
    };
    Ok(query)
}

struct QueryRecorder<'a> {
    history: &'a SqlQueryHistoryRepo,
    audit: &'a AuditRepo,
    caller: &'a Caller,
    input: &'a NormalizedInput,
    credential: Option<CredentialSnapshot>,
}

impl<'a> QueryRecorder<'a> {
    fn new(
        history: &'a SqlQueryHistoryRepo,
        audit: &'a AuditRepo,
        caller: &'a Caller,
        input: &'a NormalizedInput,
    ) -> Self {
        Self {
            history,
            audit,
            caller,
            input,
            credential: None,
        }
    }

    fn set_credential(&mut self, credential: &Credential) {
        self.credential = Some(CredentialSnapshot::from(credential));
    }

    async fn denied(&self, kind: &str, message: &str) {
        self.record("denied", Some(kind), Some(message), None).await;
    }

    async fn err(&self, kind: &str, message: &str) {
        self.record("error", Some(kind), Some(message), None).await;
    }

    async fn ok(&self, output: &SqlQueryOutput) {
        self.record("ok", None, None, Some(output)).await;
    }

    async fn record(
        &self,
        outcome: &str,
        error_kind: Option<&str>,
        error_message: Option<&str>,
        output: Option<&SqlQueryOutput>,
    ) {
        self.record_audit(outcome, error_kind, output).await;
        let credential = self.credential.as_ref();
        let params = SqlQueryHistoryParams {
            owner_user_id: credential
                .map(|credential| credential.owner_user_id)
                .or(Some(self.caller.user.id)),
            actor_user_id: Some(self.caller.user.id),
            channel: crate::audit::runtime::history_channel_str(self.caller.channel).to_owned(),
            request_id: self.caller.request_id.clone(),
            credential_id: credential.map(|credential| credential.id),
            credential_alias: credential
                .map(|credential| credential.alias.clone())
                .unwrap_or_else(|| self.input.alias.clone()),
            credential_category: credential
                .map(|credential| credential.category.as_str().to_owned())
                .unwrap_or_default(),
            credential_provider: credential
                .map(|credential| credential.provider.clone())
                .unwrap_or_default(),
            credential_env: credential
                .map(|credential| credential.env.clone())
                .unwrap_or_default(),
            query_sha256: self.input.query_sha256.clone(),
            params_count: i32::try_from(self.input.params.len()).unwrap_or(i32::MAX),
            max_rows: self.input.max_rows,
            max_bytes: i32::try_from(self.input.max_bytes).unwrap_or(i32::MAX),
            timeout_ms: i32::try_from(self.input.timeout_ms).unwrap_or(i32::MAX),
            purpose: Some(self.input.purpose.clone()),
            outcome: outcome.to_owned(),
            latency_ms: output.map(|output| output.latency_ms),
            row_count: output.map(|output| i32::try_from(output.row_count).unwrap_or(i32::MAX)),
            returned_bytes: output
                .map(|output| i32::try_from(output.returned_bytes).unwrap_or(i32::MAX)),
            truncated: output.is_some_and(|output| output.truncated),
            result_columns: output
                .map(result_column_names)
                .unwrap_or_else(|| serde_json::json!([])),
            error_kind: error_kind.map(str::to_owned),
            error_message_safe: error_message.map(crate::audit::safe::message),
        };
        if let Err(error) = self.history.insert(params).await {
            tracing::error!(event = "sql.query.history_failed", detail = %error);
        }
    }

    async fn record_audit(
        &self,
        outcome: &str,
        error_kind: Option<&str>,
        output: Option<&SqlQueryOutput>,
    ) {
        let credential = self.credential.as_ref();
        crate::audit::runtime::append_tool_event(crate::audit::runtime::ToolEventRecord {
            audit: self.audit,
            caller: self.caller,
            tool: "sql.query",
            outcome,
            credential,
            fallback_alias: &self.input.alias,
            purpose: Some(self.input.purpose.clone()),
            detail: audit_detail(self.input, credential, outcome, error_kind, output),
            failure_event: "sql.query.audit_failed",
        })
        .await;
    }
}

fn audit_detail(
    input: &NormalizedInput,
    credential: Option<&CredentialSnapshot>,
    outcome: &str,
    error_kind: Option<&str>,
    output: Option<&SqlQueryOutput>,
) -> Value {
    let mut detail = serde_json::Map::new();
    detail.insert("schema_version".to_owned(), serde_json::json!(1));
    detail.insert(
        "query_sha256".to_owned(),
        serde_json::json!(input.query_sha256),
    );
    detail.insert(
        "params_count".to_owned(),
        serde_json::json!(input.params.len()),
    );
    detail.insert("max_rows".to_owned(), serde_json::json!(input.max_rows));
    detail.insert("max_bytes".to_owned(), serde_json::json!(input.max_bytes));
    detail.insert("timeout_ms".to_owned(), serde_json::json!(input.timeout_ms));
    detail.insert("purpose".to_owned(), serde_json::json!(input.purpose));
    if let Some(credential) = credential {
        crate::audit::runtime::insert_credential_detail(
            &mut detail,
            credential.category.as_str(),
            &credential.provider,
            &credential.env,
        );
    }
    crate::audit::runtime::insert_reason_detail(&mut detail, outcome, error_kind);
    if let Some(output) = output {
        detail.insert(
            "latency_ms".to_owned(),
            serde_json::json!(output.latency_ms),
        );
        detail.insert("row_count".to_owned(), serde_json::json!(output.row_count));
        detail.insert(
            "returned_bytes".to_owned(),
            serde_json::json!(output.returned_bytes),
        );
        detail.insert("truncated".to_owned(), serde_json::json!(output.truncated));
        detail.insert("result_columns".to_owned(), result_column_names(output));
    }
    Value::Object(detail)
}

fn result_column_names(output: &SqlQueryOutput) -> Value {
    serde_json::json!(&output.column_names)
}

/// Audit row for a pre-normalization denial. Records only the channel, the
/// (pre-sanitized) alias, and denial reason — never the raw input.
fn pre_input_denial_audit_event(
    caller: &Caller,
    alias: &str,
    reason: &str,
) -> crate::audit::AuditEvent {
    crate::audit::runtime::pre_input_denial_event(caller, "sql.query", alias, reason, None)
}

/// History row for a pre-normalization denial. `error_message_safe` carries the
/// (value-free, CR/LF-stripped) validation reason; no normalized fields exist.
fn pre_input_denial_history_params(
    caller: &Caller,
    alias: &str,
    reason: &str,
    error: &Error,
) -> SqlQueryHistoryParams {
    SqlQueryHistoryParams {
        owner_user_id: Some(caller.user.id),
        actor_user_id: Some(caller.user.id),
        channel: crate::audit::runtime::history_channel_str(caller.channel).to_owned(),
        request_id: caller.request_id.clone(),
        credential_id: None,
        credential_alias: alias.to_owned(),
        credential_category: String::new(),
        credential_provider: String::new(),
        credential_env: String::new(),
        query_sha256: String::new(),
        params_count: 0,
        max_rows: 0,
        max_bytes: 0,
        timeout_ms: 0,
        purpose: None,
        outcome: "denied".to_owned(),
        latency_ms: None,
        row_count: None,
        returned_bytes: None,
        truncated: false,
        result_columns: serde_json::json!([]),
        error_kind: Some(reason.to_owned()),
        error_message_safe: Some(crate::audit::safe::message(&error.to_string())),
    }
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use opsgate_domain::credential::{CredentialPolicy, CredentialTarget};
    use uuid::Uuid;

    fn base_input() -> SqlQueryInput {
        SqlQueryInput {
            alias: "analytics".to_owned(),
            purpose: "Count recent rows".to_owned(),
            query: "select status, count(*) from payments group by status".to_owned(),
            params: Vec::new(),
            jsonpath: Vec::new(),
            max_rows: None,
            max_bytes: None,
            timeout_ms: None,
        }
    }

    fn sql_credential(policy: CredentialPolicy) -> Credential {
        let now = Utc::now();
        Credential {
            id: Uuid::nil(),
            owner_user_id: Uuid::nil(),
            category: CredentialCategory::Sql,
            provider: "postgres".to_owned(),
            alias: "analytics".to_owned(),
            target: CredentialTarget::Sql {
                database_url: "postgres://db.example.test/app?sslmode=require".to_owned(),
            },
            description: String::new(),
            env: "prod".to_owned(),
            tags: Vec::new(),
            policy,
            allow_private_network: false,
            allow_insecure_transport: false,
            has_tls_ca: false,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn input_defaults_match_docs() -> Result<()> {
        let input = normalize_input(base_input())?;
        assert!(input.jsonpath.is_empty());
        assert_eq!(input.max_rows, DEFAULT_MAX_ROWS);
        assert_eq!(input.max_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(input.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(input.params.len(), 0);
        Ok(())
    }

    #[test]
    fn input_validation_rejects_docs_boundaries() {
        let mut input = base_input();
        input.query = String::new();
        assert!(normalize_input(input.clone()).is_err());
        input = base_input();
        input.params = vec![Value::Null; MAX_PARAMS + 1];
        assert!(normalize_input(input.clone()).is_err());
        input = base_input();
        input.jsonpath = vec!["status".to_owned()];
        assert!(normalize_input(input.clone()).is_err());
        input = base_input();
        input.max_rows = Some(MAX_MAX_ROWS + 1);
        assert!(normalize_input(input).is_err());
    }

    #[test]
    fn input_validation_allows_json_array_and_object_params() -> Result<()> {
        let input = normalize_input(SqlQueryInput {
            params: vec![
                serde_json::json!(["paid", "failed"]),
                serde_json::json!({"status": "paid"}),
            ],
            ..base_input()
        })?;
        assert_eq!(input.params.len(), 2);
        let [array_param, object_param] = input.params.as_slice() else {
            return Err(Error::internal("expected two params"));
        };

        let query = sqlx::query_scalar::<_, Value>("select $1");
        assert!(bind_json_param(query, array_param).is_ok());
        let query = sqlx::query_scalar::<_, String>("explain select $1");
        assert!(bind_string_param(query, object_param).is_ok());
        Ok(())
    }

    #[test]
    fn audit_detail_stores_hash_but_not_query_params_or_values() -> Result<()> {
        let input = normalize_input(SqlQueryInput {
            query: "select secret_col from payments where token = $1".to_owned(),
            params: vec![serde_json::json!("secret-param")],
            ..base_input()
        })?;
        let rows = vec![serde_json::json!({"secret_col":"secret-value"})];
        let output = build_column_output(rows, &input, false)?;
        let credential = CredentialSnapshot::from(&sql_credential(CredentialPolicy::default()));
        let detail = audit_detail(&input, Some(&credential), "ok", None, Some(&output));
        let serialized = detail.to_string();
        assert!(serialized.contains("query_sha256"));
        assert!(serialized.contains("result_columns"));
        assert!(detail.get("shape").is_none());
        assert!(!serialized.contains("select secret_col"));
        assert!(!serialized.contains("secret-param"));
        assert!(!serialized.contains("secret-value"));
        assert!(!serialized.contains("db.example.test"));
        Ok(())
    }

    fn test_caller() -> opsgate_domain::Caller {
        let now = Utc::now();
        opsgate_domain::Caller {
            user: opsgate_domain::User {
                id: uuid::Uuid::nil(),
                sub: "sub".to_owned(),
                email: "user@example.test".to_owned(),
                display_name: "User".to_owned(),
                is_active: true,
                created_at: now,
                updated_at: now,
            },
            channel: opsgate_domain::Channel::Mcp,
            request_id: None,
            remote_ip: None,
            user_agent: None,
        }
    }

    #[test]
    fn bad_input_denial_is_recorded_safely() {
        let caller = test_caller();
        let error = Error::validation("query exceeds maximum length");

        let history = pre_input_denial_history_params(&caller, "prod", reason::BAD_INPUT, &error);
        assert_eq!(history.outcome, "denied");
        assert_eq!(history.error_kind.as_deref(), Some(reason::BAD_INPUT));
        assert!(history.purpose.is_none());
        assert_eq!(history.credential_alias, "prod");
        assert!(history.query_sha256.is_empty());
        assert_eq!(history.params_count, 0);

        let audit = pre_input_denial_audit_event(&caller, "prod", reason::BAD_INPUT).into_params();
        assert_eq!(audit.outcome, "denied");
        assert_eq!(audit.action, "mcp.sql.query");
        assert_eq!(
            audit.detail.get("denial_reason"),
            Some(&serde_json::json!(reason::BAD_INPUT))
        );
    }
}

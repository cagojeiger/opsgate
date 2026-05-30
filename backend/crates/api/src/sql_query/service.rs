use std::time::Instant;

use opsgate_core::llm_output::{
    JsonOutput, JsonOutputOptions, More, build_json_output, validate_json_paths,
};
use opsgate_core::validation::{trim_required, validate_purpose};
use opsgate_core::{Error, Result};
use opsgate_db::{AuditRepo, CredentialRepo, SqlQueryHistoryParams, SqlQueryHistoryRepo};
use opsgate_domain::credential::{Credential, CredentialCategory, CredentialPolicy};
use opsgate_domain::{Caller, Channel};
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ops::ControlFlow;

use sqlparser::ast::{Expr, ObjectName, Query, SetExpr, Statement, Visit, Visitor};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use sqlx::types::Json;
use sqlx::{Connection, Executor, PgConnection};

use crate::credential::snapshot::CredentialSnapshot;
use crate::sql_common::SqlSecret;

const DEFAULT_MAX_ROWS: i32 = 100;
const MAX_MAX_ROWS: i32 = 1000;
const DEFAULT_MAX_BYTES: usize = 64 * 1024;
const MIN_MAX_BYTES: usize = 1024;
const MAX_MAX_BYTES: usize = 1024 * 1024;
const DEFAULT_TIMEOUT_MS: u32 = 3000;
const MAX_TIMEOUT_MS: u32 = 30000;
const MAX_QUERY_LEN: usize = 16_000;
const MAX_PARAMS: usize = 64;
const BUILTIN_DENIED_FUNCTIONS: &[&str] = &[
    "dblink",
    "lo_export",
    "lo_import",
    "pg_advisory_lock",
    "pg_advisory_xact_lock",
    "pg_cancel_backend",
    "pg_read_binary_file",
    "pg_read_file",
    "pg_sleep",
    "pg_terminate_backend",
    "set_config",
];

#[derive(Clone)]
pub struct SqlQueryService {
    credentials: CredentialRepo,
    history: SqlQueryHistoryRepo,
    audit: AuditRepo,
    sealer: opsgate_core::crypto::Sealer,
}

impl SqlQueryService {
    pub fn new(
        credentials: CredentialRepo,
        history: SqlQueryHistoryRepo,
        audit: AuditRepo,
        sealer: opsgate_core::crypto::Sealer,
    ) -> Self {
        Self {
            credentials,
            history,
            audit,
            sealer,
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
                    .denied("credential_not_found", "credential not found")
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
                    "wrong_credential_provider",
                    "credential is not sql/postgres",
                )
                .await;
            return Err(Error::validation("wrong_credential_provider"));
        }
        if let Err(error) = validate_policy_boundary(&credential, &input) {
            recorder.denied("policy_denied", &error.to_string()).await;
            return Err(error);
        }
        if let Err(error) = enforce_sql_policy(&input.query, &credential.policy) {
            recorder.denied("policy_denied", &error.to_string()).await;
            return Err(error);
        }
        let secret_ciphertext = match material.secret_ciphertext {
            Some(secret_ciphertext) => secret_ciphertext,
            None => {
                recorder
                    .err("secret_destroyed", "credential secret is destroyed")
                    .await;
                return Err(Error::validation("credential secret is destroyed"));
            }
        };
        let secret = crate::sql_common::open_sql_secret(
            &self.sealer,
            &credential.alias,
            &secret_ciphertext,
        )?;
        let target = crate::target::postgres::prepare_postgres_target(
            &credential.endpoint,
            credential.allow_private_network,
        )
        .await?;

        let started = Instant::now();
        let mut output = match execute_postgres(&target, &secret, &input).await {
            Ok(output) => output,
            Err(error) => {
                recorder.err("query_failed", "sql query failed").await;
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
        self.record_pre_input_denial(caller, alias, "bad_input", error)
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
pub struct SqlQueryInput {
    pub alias: String,
    pub purpose: String,
    pub query: String,
    #[serde(default)]
    #[schemars(schema_with = "opsgate_core::schema::json_value_array_schema")]
    pub params: Vec<Value>,
    #[serde(default)]
    pub jsonpath: Vec<String>,
    pub max_rows: Option<i32>,
    pub max_bytes: Option<usize>,
    pub timeout_ms: Option<u32>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SqlQueryOutput {
    #[schemars(schema_with = "opsgate_core::schema::json_value_schema")]
    pub body: Value,
    pub row_count: usize,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub more: Option<More>,
    #[allow(dead_code)]
    #[serde(skip)]
    pub original_bytes: usize,
    #[serde(skip)]
    pub returned_bytes: usize,
    #[serde(skip)]
    pub latency_ms: i64,
    #[serde(skip)]
    pub column_names: Vec<String>,
}

#[derive(Debug, Clone)]
struct NormalizedInput {
    alias: String,
    purpose: String,
    query: String,
    params: Vec<Value>,
    jsonpath: Vec<String>,
    max_rows: i32,
    max_bytes: usize,
    timeout_ms: u32,
    query_sha256: String,
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

fn validate_policy_boundary(credential: &Credential, input: &NormalizedInput) -> Result<()> {
    let policy = &credential.policy;
    if policy.allow_explain_analyze && !policy.allow_explain {
        return Err(Error::validation("sql policy is invalid"));
    }
    if policy.max_rows > 0 && input.max_rows > i32::try_from(policy.max_rows).unwrap_or(i32::MAX) {
        return Err(Error::validation("max_rows exceeds credential policy"));
    }
    if policy.max_bytes > 0
        && input.max_bytes > usize::try_from(policy.max_bytes).unwrap_or(usize::MAX)
    {
        return Err(Error::validation("max_bytes exceeds credential policy"));
    }
    if policy.timeout_ms > 0 && input.timeout_ms > policy.timeout_ms {
        return Err(Error::validation("timeout_ms exceeds credential policy"));
    }
    Ok(())
}

fn enforce_sql_policy(query: &str, policy: &CredentialPolicy) -> Result<()> {
    let dialect = PostgreSqlDialect {};
    let statements = Parser::parse_sql(&dialect, query)
        .map_err(|error| Error::validation(format!("query has SQL syntax error: {error}")))?;
    if statements.len() != 1 {
        return Err(Error::validation(format!(
            "query must contain exactly one statement, got {}",
            statements.len()
        )));
    }
    let statement = statements
        .first()
        .ok_or_else(|| Error::validation("query statement is empty"))?;
    match statement {
        Statement::Query(query) => validate_query_ast(query),
        Statement::Explain {
            analyze, statement, ..
        } => {
            if !policy.allow_explain {
                return Err(Error::validation(
                    "EXPLAIN is not allowed by credential policy",
                ));
            }
            if *analyze && !policy.allow_explain_analyze {
                return Err(Error::validation(
                    "EXPLAIN ANALYZE is not allowed by credential policy",
                ));
            }
            match statement.as_ref() {
                Statement::Query(query) => validate_query_ast(query),
                _ => Err(Error::validation(
                    "EXPLAIN is only allowed for SELECT/WITH queries",
                )),
            }
        }
        _ => Err(Error::validation(
            "query must be a single SELECT/WITH statement or policy-approved EXPLAIN",
        )),
    }?;
    enforce_ast_policy(statement, policy)
}

fn validate_query_ast(query: &Query) -> Result<()> {
    if !query.locks.is_empty() {
        return Err(Error::validation("SELECT locking clauses are not allowed"));
    }
    // Reject data-modifying CTEs (`WITH x AS (INSERT ... RETURNING) ...`) at the
    // policy layer instead of relying on the BEGIN READ ONLY runtime backstop.
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            validate_query_ast(&cte.query)?;
        }
    }
    validate_set_expr(&query.body)
}

fn validate_set_expr(expr: &SetExpr) -> Result<()> {
    match expr {
        SetExpr::Select(select) => {
            if select.into.is_some() {
                return Err(Error::validation("SELECT INTO is not allowed"));
            }
            Ok(())
        }
        SetExpr::Query(query) => validate_query_ast(query),
        SetExpr::SetOperation { left, right, .. } => {
            validate_set_expr(left)?;
            validate_set_expr(right)
        }
        _ => Err(Error::validation(
            "query contains a statement type that sql.query does not allow",
        )),
    }
}

/// Enforce metadata/function denials on the parsed AST rather than the raw
/// query text. Walking real syntax nodes is immune to whitespace/quoting
/// evasions (e.g. `pg_sleep (10)`, `pg_catalog .pg_tables`) and avoids false
/// positives on legitimate `pg_`-prefixed identifiers used outside relations.
fn enforce_ast_policy(statement: &Statement, policy: &CredentialPolicy) -> Result<()> {
    let mut visitor = SqlPolicyVisitor {
        policy,
        violation: None,
    };
    let _ = statement.visit(&mut visitor);
    match visitor.violation {
        Some(message) => Err(Error::validation(message)),
        None => Ok(()),
    }
}

struct SqlPolicyVisitor<'a> {
    policy: &'a CredentialPolicy,
    violation: Option<String>,
}

impl Visitor for SqlPolicyVisitor<'_> {
    type Break = ();

    fn pre_visit_relation(&mut self, name: &ObjectName) -> ControlFlow<Self::Break> {
        if !self.policy.allow_metadata && is_metadata_relation(name) {
            self.violation =
                Some("Postgres metadata access is not allowed by credential policy".to_owned());
            return ControlFlow::Break(());
        }
        // A table function (`FROM dblink(...)`) surfaces here as a relation name,
        // never as `Expr::Function`, so apply the function denylist to it too.
        self.check_function_name(name, true)
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        match expr {
            // Function calls (`pg_sleep(...)`): match on the parsed call name.
            Expr::Function(function) => self.check_function_name(&function.name, true),
            // Niladic value functions (`current_user`) may parse as identifiers;
            // only the credential's denylist applies (not the builtin call list).
            Expr::Identifier(ident) => {
                let candidate = ident.value.trim().to_ascii_lowercase();
                self.check_function_candidates(&candidate, &candidate, false)
            }
            Expr::CompoundIdentifier(parts) => match parts.last() {
                Some(ident) => {
                    let candidate = ident.value.trim().to_ascii_lowercase();
                    self.check_function_candidates(&candidate, &candidate, false)
                }
                None => ControlFlow::Continue(()),
            },
            _ => ControlFlow::Continue(()),
        }
    }
}

impl SqlPolicyVisitor<'_> {
    fn check_function_name(&mut self, name: &ObjectName, is_call: bool) -> ControlFlow<()> {
        let parts = object_name_parts(name);
        let Some(short) = parts.last() else {
            return ControlFlow::Continue(());
        };
        if is_call
            && !self.policy.allow_metadata
            && parts.len() > 1
            && let Some(schema) = parts.first().filter(|schema| is_metadata_schema(schema))
        {
            self.violation = Some(format!(
                "function schema {schema:?} is not allowed by credential policy"
            ));
            return ControlFlow::Break(());
        }
        let full = parts.join(".");
        self.check_function_candidates(&full, short, is_call)
    }

    /// Check a function/relation name against the builtin (call sites only) and
    /// credential-policy denylists, recording the first violation.
    fn check_function_candidates(
        &mut self,
        full_candidate: &str,
        short_candidate: &str,
        is_call: bool,
    ) -> ControlFlow<()> {
        if is_call
            && BUILTIN_DENIED_FUNCTIONS
                .iter()
                .any(|denied| denied == &short_candidate || denied == &full_candidate)
        {
            self.violation = Some(format!(
                "function {full_candidate:?} is blocked by built-in SQL policy"
            ));
            return ControlFlow::Break(());
        }
        if self.denied_policy_function(full_candidate, short_candidate) {
            self.violation = Some(format!(
                "function {full_candidate:?} is denied by credential policy"
            ));
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }

    /// Match Go parity: unqualified denied names match any schema, while
    /// qualified denied names match only the exact full call name.
    fn denied_policy_function(&self, full_candidate: &str, short_candidate: &str) -> bool {
        self.policy
            .denied_functions
            .iter()
            .map(|denied| denied.trim().to_ascii_lowercase())
            .any(|denied| {
                if denied.is_empty() {
                    false
                } else if denied.contains('.') {
                    denied == full_candidate
                } else {
                    denied == short_candidate
                }
            })
    }
}

/// Postgres catalog/metadata relation: schema-qualified `pg_catalog`/
/// `information_schema`, or an unqualified `pg_`-prefixed catalog table.
fn is_metadata_relation(name: &ObjectName) -> bool {
    let parts = object_name_parts(name);
    match parts.as_slice() {
        [] => false,
        [table] => table.starts_with("pg_"),
        [.., schema, _table] => is_metadata_schema(schema),
    }
}

fn object_name_parts(name: &ObjectName) -> Vec<String> {
    name.0
        .iter()
        .filter_map(|part| part.as_ident())
        .map(|ident| ident.value.trim().to_ascii_lowercase())
        .collect()
}

fn is_metadata_schema(schema: &str) -> bool {
    matches!(schema, "pg_catalog" | "information_schema")
}

async fn execute_postgres(
    target: &crate::target::postgres::GuardedPostgresTarget,
    secret: &SqlSecret,
    input: &NormalizedInput,
) -> Result<SqlQueryOutput> {
    let options = target.connect_options(
        secret.username.expose_secret(),
        secret.password.expose_secret(),
    )?;
    let mut conn = PgConnection::connect_with(&options)
        .await
        .map_err(|_error| Error::internal("postgres connection failed"))?;
    conn.execute("BEGIN READ ONLY")
        .await
        .map_err(|_error| Error::internal("postgres transaction failed"))?;
    if let Err(error) = set_statement_timeout(&mut conn, input.timeout_ms).await {
        let _ = conn.execute("ROLLBACK").await;
        return Err(error);
    }
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
    if result.is_ok() {
        conn.execute("COMMIT")
            .await
            .map_err(|_error| Error::internal("postgres transaction commit failed"))?;
    } else {
        let _ = conn.execute("ROLLBACK").await;
    }
    result
}

async fn set_statement_timeout(conn: &mut PgConnection, timeout_ms: u32) -> Result<()> {
    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(format!("{timeout_ms}ms"))
        .execute(conn)
        .await
        .map_err(|_error| Error::internal("postgres statement timeout setup failed"))?;
    Ok(())
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
    let mut rows = value.as_array().cloned().unwrap_or_default();
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

fn build_column_output(
    rows: Vec<Value>,
    input: &NormalizedInput,
    truncated: bool,
) -> Result<SqlQueryOutput> {
    let row_count = rows.len();
    let (body, column_names) = transpose_rows(rows)?;
    let bytes = serde_json::to_vec(&body)
        .map_err(|error| Error::internal(format!("serialize sql query body: {error}")))?;
    let shaped = build_shaped_body(&bytes, input)?;
    let column_names = if input.jsonpath.is_empty() {
        column_names
    } else {
        Vec::new()
    };

    Ok(SqlQueryOutput {
        body: shaped.body,
        row_count,
        truncated: truncated || shaped.truncated,
        more: shaped.more,
        original_bytes: shaped.original_bytes,
        returned_bytes: shaped.returned_bytes,
        latency_ms: 0,
        column_names,
    })
}

fn build_shaped_body(bytes: &[u8], input: &NormalizedInput) -> Result<JsonOutput> {
    build_json_output(
        bytes,
        JsonOutputOptions {
            max_bytes: input.max_bytes,
            max_allowed_bytes: MAX_MAX_BYTES,
            json_paths: input.jsonpath.clone(),
            transport_truncated: false,
            original_bytes: None,
        },
    )
}

fn transpose_rows(rows: Vec<Value>) -> Result<(Value, Vec<String>)> {
    let mut column_names = Vec::<String>::new();
    let mut column_values = Vec::<Vec<Value>>::new();

    for (row_index, row) in rows.into_iter().enumerate() {
        let object = row
            .as_object()
            .ok_or_else(|| Error::internal("sql result row is not an object"))?;
        for key in object.keys() {
            if !column_names.iter().any(|name| name == key) {
                column_names.push(key.clone());
                column_values.push(vec![Value::Null; row_index]);
            }
        }
        for (name, values) in column_names.iter().zip(column_values.iter_mut()) {
            values.push(object.get(name).cloned().unwrap_or(Value::Null));
        }
    }

    let mut object = serde_json::Map::new();
    for (name, values) in column_names.iter().cloned().zip(column_values) {
        object.insert(name, Value::Array(values));
    }
    Ok((Value::Object(object), column_names))
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
            channel: channel_str(self.caller.channel).to_owned(),
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
        let event = crate::audit::runtime::tool_event(
            self.caller,
            "sql.query",
            outcome,
            credential.map(|credential| credential.id.to_string()),
            credential
                .map(|credential| credential.alias.clone())
                .unwrap_or_else(|| self.input.alias.clone()),
            Some(self.input.purpose.clone()),
            audit_detail(self.input, credential, outcome, error_kind, output),
        );
        crate::audit::append_event(self.audit, event, "sql.query.audit_failed").await;
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
        detail.insert(
            "credential_category".to_owned(),
            serde_json::json!(credential.category.as_str()),
        );
        detail.insert(
            "credential_provider".to_owned(),
            serde_json::json!(credential.provider),
        );
        detail.insert(
            "credential_env".to_owned(),
            serde_json::json!(credential.env),
        );
    }
    if let Some(error_kind) = error_kind {
        let key = if outcome == "denied" {
            "denial_reason"
        } else {
            "error_kind"
        };
        detail.insert(key.to_owned(), serde_json::json!(error_kind));
    }
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
        channel: channel_str(caller.channel).to_owned(),
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

fn channel_str(channel: Channel) -> &'static str {
    match channel {
        Channel::Api => "api",
        Channel::Mcp | Channel::Browser => "mcp",
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
    use opsgate_domain::credential::CredentialPolicy;
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
            endpoint: "postgres://db.example.test/app".to_owned(),
            description: String::new(),
            env: "prod".to_owned(),
            tags: Vec::new(),
            policy,
            allow_private_network: false,
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
    fn policy_boundary_rejects_budget_overrides() -> Result<()> {
        let credential = sql_credential(CredentialPolicy {
            max_rows: 10,
            max_bytes: 2048,
            timeout_ms: 1000,
            ..CredentialPolicy::default()
        });
        let mut input = normalize_input(base_input())?;
        input.max_rows = 11;
        assert!(validate_policy_boundary(&credential, &input).is_err());
        input.max_rows = 10;
        input.max_bytes = 4096;
        assert!(validate_policy_boundary(&credential, &input).is_err());
        input.max_bytes = 2048;
        input.timeout_ms = 1001;
        assert!(validate_policy_boundary(&credential, &input).is_err());
        Ok(())
    }

    #[test]
    fn ast_policy_allows_select_and_with() {
        let policy = CredentialPolicy::default();
        assert!(enforce_sql_policy("select 1", &policy).is_ok());
        assert!(
            enforce_sql_policy("select * from payments where created_at >= $1", &policy).is_ok()
        );
        assert!(enforce_sql_policy("with x as (select 1) select * from x", &policy).is_ok());
    }

    #[test]
    fn ast_policy_rejects_write_lock_metadata_and_functions() {
        let policy = CredentialPolicy::default();
        assert!(enforce_sql_policy("delete from users", &policy).is_err());
        assert!(enforce_sql_policy("select * from users for update", &policy).is_err());
        assert!(enforce_sql_policy("select pg_sleep(10)", &policy).is_err());
        assert!(enforce_sql_policy("select * from pg_catalog.pg_tables", &policy).is_err());
    }

    #[test]
    fn ast_policy_denies_metadata_schema_functions_without_allow_metadata() {
        let policy = CredentialPolicy::default();
        assert!(
            enforce_sql_policy(
                "select pg_catalog.obj_description(1259, 'pg_class')",
                &policy
            )
            .is_err()
        );
        assert!(
            enforce_sql_policy(
                "select information_schema._pg_char_max_length(1043, 10)",
                &policy,
            )
            .is_err()
        );
    }

    #[test]
    fn ast_policy_allows_metadata_schema_functions_when_allow_metadata_enabled() {
        let policy = CredentialPolicy {
            allow_metadata: true,
            ..CredentialPolicy::default()
        };
        assert!(
            enforce_sql_policy(
                "select pg_catalog.obj_description(1259, 'pg_class')",
                &policy
            )
            .is_ok()
        );
        assert!(
            enforce_sql_policy(
                "select information_schema._pg_char_max_length(1043, 10)",
                &policy,
            )
            .is_ok()
        );
    }

    #[test]
    fn ast_policy_denies_builtin_functions_after_metadata_is_allowed() {
        let policy = CredentialPolicy {
            allow_metadata: true,
            ..CredentialPolicy::default()
        };
        assert!(enforce_sql_policy("select pg_catalog.pg_sleep(1)", &policy).is_err());
    }

    #[test]
    fn ast_policy_matches_denied_functions_by_short_or_exact_full_name() {
        let policy = CredentialPolicy {
            allow_metadata: true,
            denied_functions: vec!["custom_blocked".to_owned()],
            ..CredentialPolicy::default()
        };
        assert!(enforce_sql_policy("select custom_blocked()", &policy).is_err());
        assert!(enforce_sql_policy("select public.custom_blocked()", &policy).is_err());

        let policy = CredentialPolicy {
            allow_metadata: true,
            denied_functions: vec!["public.custom_blocked".to_owned()],
            ..CredentialPolicy::default()
        };
        assert!(enforce_sql_policy("select public.custom_blocked()", &policy).is_err());
        assert!(enforce_sql_policy("select custom_blocked()", &policy).is_ok());
        assert!(enforce_sql_policy("select other.custom_blocked()", &policy).is_ok());
    }

    #[test]
    fn ast_policy_blocks_whitespace_and_quoting_evasions() {
        let policy = CredentialPolicy::default();
        // Whitespace between function name and `(` defeated the old substring needle.
        assert!(enforce_sql_policy("select pg_sleep (10)", &policy).is_err());
        // Unqualified catalog table (no `pg_catalog.` prefix to substring-match).
        assert!(enforce_sql_policy("select * from pg_stat_activity", &policy).is_err());
        assert!(enforce_sql_policy("select * from information_schema.tables", &policy).is_err());
    }

    #[test]
    fn ast_policy_no_false_positive_on_pg_prefixed_alias() {
        // `pg_total` is a column alias, not a relation or denied function: allowed.
        let policy = CredentialPolicy::default();
        assert!(enforce_sql_policy("select count(*) as pg_total from payments", &policy).is_ok());
    }

    #[test]
    fn ast_policy_blocks_table_functions_in_from() {
        // Table functions surface as a relation, not Expr::Function; the builtin
        // denylist must still catch them (regression: dblink is not pg_-prefixed
        // so the metadata gate alone misses it).
        let policy = CredentialPolicy::default();
        assert!(
            enforce_sql_policy("select * from dblink('h','select 1') as t(a int)", &policy)
                .is_err()
        );
        // Policy-denied function in FROM position is rejected too.
        let policy = CredentialPolicy {
            denied_functions: vec!["my_udf".to_owned()],
            ..CredentialPolicy::default()
        };
        assert!(enforce_sql_policy("select * from my_udf(1)", &policy).is_err());
    }

    #[test]
    fn ast_policy_blocks_data_modifying_cte() {
        let policy = CredentialPolicy::default();
        assert!(
            enforce_sql_policy(
                "with x as (insert into t values (1) returning id) select * from x",
                &policy,
            )
            .is_err()
        );
    }

    #[test]
    fn ast_policy_rejects_denied_sql_value_function() {
        let policy = CredentialPolicy {
            denied_functions: vec!["current_user".to_owned()],
            ..CredentialPolicy::default()
        };
        assert!(enforce_sql_policy("select current_user", &policy).is_err());
    }

    #[test]
    fn ast_policy_requires_explain_permission() {
        assert!(enforce_sql_policy("explain select 1", &CredentialPolicy::default()).is_err());
        let policy = CredentialPolicy {
            allow_explain: true,
            ..CredentialPolicy::default()
        };
        assert!(enforce_sql_policy("explain select 1", &policy).is_ok());
        assert!(enforce_sql_policy("explain analyze select 1", &policy).is_err());
    }

    #[test]
    fn flat_rows_become_column_oriented_body() -> Result<()> {
        let rows = vec![
            serde_json::json!({"status":"failed", "total": 42}),
            serde_json::json!({"status":"paid", "region": "us"}),
        ];
        let input = normalize_input(base_input())?;
        let output = build_column_output(rows, &input, false)?;

        assert_eq!(output.row_count, 2);
        assert_eq!(
            output.column_names,
            vec![
                "status".to_owned(),
                "total".to_owned(),
                "region".to_owned()
            ]
        );
        assert_eq!(
            output.body,
            serde_json::json!({
                "status": ["failed", "paid"],
                "total": [42, null],
                "region": [null, "us"]
            })
        );
        Ok(())
    }

    #[test]
    fn jsonpath_projects_one_column() -> Result<()> {
        let rows = vec![
            serde_json::json!({"status":"failed", "total": 42}),
            serde_json::json!({"status":"paid", "total": 900}),
        ];
        let input = normalize_input(SqlQueryInput {
            jsonpath: vec!["$.status".to_owned()],
            ..base_input()
        })?;
        let output = build_column_output(rows, &input, false)?;

        let projected = output
            .body
            .get("$.status")
            .ok_or_else(|| Error::internal("missing projected column"))?;
        assert_eq!(projected, &serde_json::json!([["failed", "paid"]]));
        assert_eq!(output.row_count, 2);
        assert!(output.column_names.is_empty());
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
        assert!(!serialized.contains("endpoint"));
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

        let history = pre_input_denial_history_params(&caller, "prod", "bad_input", &error);
        assert_eq!(history.outcome, "denied");
        assert_eq!(history.error_kind.as_deref(), Some("bad_input"));
        assert!(history.purpose.is_none());
        assert_eq!(history.credential_alias, "prod");
        assert!(history.query_sha256.is_empty());
        assert_eq!(history.params_count, 0);

        let audit = pre_input_denial_audit_event(&caller, "prod", "bad_input").into_params();
        assert_eq!(audit.outcome, "denied");
        assert_eq!(audit.action, "mcp.sql.query");
        assert_eq!(
            audit.detail.get("denial_reason"),
            Some(&serde_json::json!("bad_input"))
        );
    }
}

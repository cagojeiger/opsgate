use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Instant;

use opsgate_core::net::ssrf::is_blocked_target_ip;
use opsgate_core::validation::{trim_required, validate_purpose};
use opsgate_core::{Error, Result};
use opsgate_db::{
    AuditLogParams, AuditRepo, CredentialRepo, SqlQueryHistoryParams, SqlQueryHistoryRepo,
};
use opsgate_domain::credential::{Credential, CredentialCategory, CredentialPolicy};
use opsgate_domain::{Caller, Channel};
use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretString};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlparser::ast::{Query, SetExpr, Statement};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, Executor, PgConnection};
use uuid::Uuid;

const SHAPE_ROWS: &str = "rows";
const SHAPE_COLUMNS: &str = "columns";
const SHAPE_VALUES: &str = "values";
const DEFAULT_SHAPE: &str = SHAPE_ROWS;
const DEFAULT_MAX_ROWS: i32 = 100;
const MAX_MAX_ROWS: i32 = 1000;
const DEFAULT_MAX_BYTES: usize = 64 * 1024;
const MIN_MAX_BYTES: usize = 1024;
const MAX_MAX_BYTES: usize = 1024 * 1024;
const DEFAULT_TIMEOUT_MS: u32 = 3000;
const MAX_TIMEOUT_MS: u32 = 30000;
const MAX_QUERY_LEN: usize = 16_000;
const MAX_PARAMS: usize = 64;
const SECRET_DOMAIN: &str = "credentials";

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
        let input = normalize_input(input)?;
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
        let secret = self.open_sql_secret(&credential.alias, &secret_ciphertext)?;
        if !credential.allow_private_network {
            validate_target_ips(&credential.endpoint).await?;
        }

        let started = Instant::now();
        let mut output = match execute_postgres(&credential.endpoint, &secret, &input).await {
            Ok(output) => output,
            Err(error) => {
                recorder.err("query_failed", "sql query failed").await;
                return Err(error);
            }
        };
        output.latency_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        finalize_output(&mut output, &input, &credential.policy)?;
        recorder.ok(&output).await;
        Ok(output)
    }

    fn open_sql_secret(&self, alias: &str, ciphertext: &[u8]) -> Result<SqlSecret> {
        let plaintext = self.sealer.open(SECRET_DOMAIN, alias, ciphertext)?;
        serde_json::from_slice::<SqlSecret>(&plaintext)
            .map_err(|error| Error::internal(format!("decode sql credential secret: {error}")))
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
    pub shape: String,
    pub max_rows: Option<i32>,
    pub max_bytes: Option<usize>,
    pub timeout_ms: Option<u32>,
}

#[derive(Debug, Clone, JsonSchema)]
pub struct SqlQueryOutput {
    pub columns: Vec<Column>,
    #[schemars(schema_with = "opsgate_core::schema::json_object_array_schema")]
    pub rows: Vec<BTreeMap<String, Value>>,
    pub shape: String,
    #[schemars(schema_with = "opsgate_core::schema::json_value_columns_schema")]
    pub data: BTreeMap<String, Vec<Value>>,
    pub column: Option<Column>,
    #[schemars(schema_with = "opsgate_core::schema::json_value_array_schema")]
    pub values: Vec<Value>,
    pub row_count: usize,
    pub truncated: bool,
    pub returned_bytes: usize,
    pub truncated_columns: Vec<String>,
    pub more: Option<More>,
    pub latency_ms: i64,
}

impl Serialize for SqlQueryOutput {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut fields = 6;
        if self.shape != SHAPE_ROWS {
            fields += 1;
        }
        if self.shape == SHAPE_COLUMNS {
            fields += 1;
        } else if self.shape == SHAPE_VALUES {
            fields += 2;
        } else {
            fields += 1;
        }
        if !self.truncated_columns.is_empty() {
            fields += 1;
        }
        if self.more.is_some() {
            fields += 1;
        }
        let mut map = serializer.serialize_map(Some(fields))?;
        map.serialize_entry("columns", &self.columns)?;
        if self.shape == SHAPE_COLUMNS {
            map.serialize_entry("shape", SHAPE_COLUMNS)?;
            map.serialize_entry("data", &self.data)?;
        } else if self.shape == SHAPE_VALUES {
            map.serialize_entry("shape", SHAPE_VALUES)?;
            if let Some(column) = &self.column {
                map.serialize_entry("column", column)?;
            }
            map.serialize_entry("values", &self.values)?;
        } else {
            map.serialize_entry("rows", &self.rows)?;
        }
        map.serialize_entry("row_count", &self.row_count)?;
        map.serialize_entry("truncated", &self.truncated)?;
        map.serialize_entry("returned_bytes", &self.returned_bytes)?;
        if !self.truncated_columns.is_empty() {
            map.serialize_entry("truncated_columns", &self.truncated_columns)?;
        }
        if let Some(more) = &self.more {
            map.serialize_entry("more", more)?;
        }
        map.serialize_entry("latency_ms", &self.latency_ms)?;
        map.end()
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Column {
    pub name: String,
    #[serde(rename = "type")]
    pub data_type: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct More {
    pub options: MoreOption,
    pub hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct MoreOption {
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub suggested_max_rows: i32,
    #[serde(skip_serializing_if = "is_zero_usize", default)]
    pub suggested_max_bytes: usize,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub suggested_shape: String,
    #[serde(skip_serializing_if = "is_false", default)]
    pub use_where: bool,
    #[serde(skip_serializing_if = "is_false", default)]
    pub use_aggregate: bool,
    #[serde(skip_serializing_if = "is_false", default)]
    pub use_keyset_pagination: bool,
    #[serde(skip_serializing_if = "is_false", default)]
    pub select_fewer_columns: bool,
}

#[derive(Debug, Clone)]
struct NormalizedInput {
    alias: String,
    purpose: String,
    query: String,
    params: Vec<Value>,
    shape: String,
    max_rows: i32,
    max_bytes: usize,
    timeout_ms: u32,
    query_sha256: String,
}

#[derive(Debug, Deserialize)]
struct SqlSecret {
    username: SecretString,
    password: SecretString,
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
    for param in &input.params {
        validate_param(param)?;
    }
    let shape = if input.shape.trim().is_empty() {
        DEFAULT_SHAPE.to_owned()
    } else {
        input.shape.trim().to_ascii_lowercase()
    };
    if !matches!(shape.as_str(), SHAPE_ROWS | SHAPE_COLUMNS | SHAPE_VALUES) {
        return Err(Error::validation(
            "shape must be one of rows, columns, values",
        ));
    }
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
        shape,
        max_rows,
        max_bytes,
        timeout_ms,
        query_sha256,
    })
}

fn validate_param(value: &Value) -> Result<()> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
        Value::Array(_) | Value::Object(_) => Err(Error::validation(
            "params must contain only null, boolean, number, or string values",
        )),
    }
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
    validate_text_policy(query, policy)
}

fn validate_query_ast(query: &Query) -> Result<()> {
    if !query.locks.is_empty() {
        return Err(Error::validation("SELECT locking clauses are not allowed"));
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

fn validate_text_policy(query: &str, policy: &CredentialPolicy) -> Result<()> {
    let lower = query.to_ascii_lowercase();
    if !policy.allow_metadata && contains_metadata_access(&lower) {
        return Err(Error::validation(
            "Postgres metadata access is not allowed by credential policy",
        ));
    }
    if contains_locking_clause(&lower) {
        return Err(Error::validation("SELECT locking clauses are not allowed"));
    }
    for function in BUILTIN_DENIED_FUNCTIONS {
        if contains_function(&lower, function) {
            return Err(Error::validation(format!(
                "function {function:?} is blocked by built-in SQL policy"
            )));
        }
    }
    for function in &policy.denied_functions {
        let denied = function.trim().to_ascii_lowercase();
        if !denied.is_empty()
            && (contains_function(&lower, &denied) || contains_sql_value_function(&lower, &denied))
        {
            return Err(Error::validation(format!(
                "function {denied:?} is denied by credential policy"
            )));
        }
    }
    Ok(())
}

fn contains_metadata_access(lower: &str) -> bool {
    lower.contains("pg_catalog.")
        || lower.contains("information_schema.")
        || lower.contains("from pg_")
        || lower.contains("join pg_")
}

fn contains_locking_clause(lower: &str) -> bool {
    lower.contains(" for update")
        || lower.contains(" for no key update")
        || lower.contains(" for share")
        || lower.contains(" for key share")
}

fn contains_function(lower: &str, name: &str) -> bool {
    let short = name.rsplit('.').next().unwrap_or(name);
    contains_function_like(lower, short)
        || (name.contains('.') && contains_function_like(lower, name))
}

fn contains_function_like(lower: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let needle = format!("{name}(");
    lower.contains(&needle)
}

fn contains_sql_value_function(lower: &str, name: &str) -> bool {
    let needles = [
        format!("select {name}"),
        format!(", {name}"),
        format!("({name}"),
        format!(" {name} "),
    ];
    needles.iter().any(|needle| lower.contains(needle))
}

async fn execute_postgres(
    endpoint: &str,
    secret: &SqlSecret,
    input: &NormalizedInput,
) -> Result<SqlQueryOutput> {
    let options = PgConnectOptions::from_str(endpoint)
        .map_err(|error| Error::validation(format!("postgres endpoint: {error}")))?
        .username(secret.username.expose_secret())
        .password(secret.password.expose_secret());
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
    build_output(rows, &input.shape, truncated)
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
    build_output(rows, &input.shape, truncated)
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
        Value::Array(_) | Value::Object(_) => {
            return Err(Error::validation(
                "params must contain only null, boolean, number, or string values",
            ));
        }
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
        Value::Array(_) | Value::Object(_) => {
            return Err(Error::validation(
                "params must contain only null, boolean, number, or string values",
            ));
        }
    };
    Ok(query)
}

fn build_output(rows: Vec<Value>, shape: &str, truncated: bool) -> Result<SqlQueryOutput> {
    let mut object_rows = Vec::with_capacity(rows.len());
    for row in rows {
        let object = row
            .as_object()
            .ok_or_else(|| Error::internal("sql result row is not an object"))?;
        object_rows.push(
            object
                .iter()
                .map(|(key, value)| (key.clone(), compact_json_value(value.clone())))
                .collect::<BTreeMap<_, _>>(),
        );
    }
    let columns = infer_columns(&object_rows);
    let mut output = SqlQueryOutput {
        columns,
        rows: Vec::new(),
        shape: shape.to_owned(),
        data: BTreeMap::new(),
        column: None,
        values: Vec::new(),
        row_count: object_rows.len(),
        truncated,
        returned_bytes: 0,
        truncated_columns: Vec::new(),
        more: None,
        latency_ms: 0,
    };
    match shape {
        SHAPE_COLUMNS => {
            output.data = columns_shape(&output.columns, &object_rows);
        }
        SHAPE_VALUES => {
            if output.columns.len() != 1 {
                return Err(Error::validation(
                    "shape=values requires exactly one result column",
                ));
            }
            let column = output
                .columns
                .first()
                .cloned()
                .ok_or_else(|| Error::validation("shape=values requires one result column"))?;
            output.values = object_rows
                .iter()
                .map(|row| row.get(&column.name).cloned().unwrap_or(Value::Null))
                .collect();
            output.column = Some(column);
        }
        _ => {
            output.rows = object_rows;
        }
    }
    Ok(output)
}

fn infer_columns(rows: &[BTreeMap<String, Value>]) -> Vec<Column> {
    let Some(first) = rows.first() else {
        return Vec::new();
    };
    first
        .iter()
        .map(|(name, value)| Column {
            name: name.clone(),
            data_type: json_type(value).to_owned(),
        })
        .collect()
}

fn columns_shape(
    columns: &[Column],
    rows: &[BTreeMap<String, Value>],
) -> BTreeMap<String, Vec<Value>> {
    let mut data = columns
        .iter()
        .map(|column| (column.name.clone(), Vec::with_capacity(rows.len())))
        .collect::<BTreeMap<_, _>>();
    for row in rows {
        for column in columns {
            if let Some(values) = data.get_mut(&column.name) {
                values.push(row.get(&column.name).cloned().unwrap_or(Value::Null));
            }
        }
    }
    data
}

fn compact_json_value(value: Value) -> Value {
    match value {
        Value::String(text) if text.len() > 4096 => {
            let prefix = text.chars().take(4096).collect::<String>();
            Value::String(format!("{prefix}…[truncated]"))
        }
        other => other,
    }
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "text",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn finalize_output(
    output: &mut SqlQueryOutput,
    input: &NormalizedInput,
    policy: &CredentialPolicy,
) -> Result<()> {
    output.returned_bytes = encoded_len(output)?;
    while output.returned_bytes > input.max_bytes && remove_last_value(output) {
        output.truncated = true;
        output.returned_bytes = encoded_len(output)?;
    }
    if output.returned_bytes > input.max_bytes {
        output.more = None;
        output.truncated = true;
        clear_values(output);
        output.returned_bytes = encoded_len(output)?;
    }
    if output.truncated {
        attach_more(output, input, policy);
        output.returned_bytes = encoded_len(output)?;
        if output.returned_bytes > input.max_bytes {
            output.more = None;
            output.returned_bytes = encoded_len(output)?;
        }
    }
    Ok(())
}

fn remove_last_value(output: &mut SqlQueryOutput) -> bool {
    if output.shape == SHAPE_COLUMNS {
        let Some(column) = output.columns.last() else {
            return false;
        };
        let name = column.name.clone();
        if let Some(values) = output.data.get_mut(&name)
            && values.pop().is_some()
        {
            output.row_count = min_column_len(&output.data);
            return true;
        }
        output.data.remove(&name);
        output.truncated_columns.push(name);
        output.columns.pop();
        return true;
    }
    if output.shape == SHAPE_VALUES {
        if output.values.pop().is_some() {
            output.row_count = output.values.len();
            return true;
        }
        return false;
    }
    if output.rows.pop().is_some() {
        output.row_count = output.rows.len();
        return true;
    }
    false
}

fn min_column_len(data: &BTreeMap<String, Vec<Value>>) -> usize {
    data.values().map(Vec::len).min().unwrap_or(0)
}

fn clear_values(output: &mut SqlQueryOutput) {
    output.rows.clear();
    output.data.clear();
    output.values.clear();
    output.row_count = 0;
}

fn attach_more(output: &mut SqlQueryOutput, input: &NormalizedInput, policy: &CredentialPolicy) {
    let row_limit = if policy.max_rows > 0 {
        i32::try_from(policy.max_rows)
            .unwrap_or(MAX_MAX_ROWS)
            .min(MAX_MAX_ROWS)
    } else {
        MAX_MAX_ROWS
    };
    let byte_limit = if policy.max_bytes > 0 {
        usize::try_from(policy.max_bytes)
            .unwrap_or(MAX_MAX_BYTES)
            .min(MAX_MAX_BYTES)
    } else {
        MAX_MAX_BYTES
    };
    let row_limited = output.row_count >= usize::try_from(input.max_rows).unwrap_or(usize::MAX);
    let mut options = MoreOption {
        suggested_max_rows: 0,
        suggested_max_bytes: 0,
        suggested_shape: String::new(),
        use_where: true,
        use_aggregate: true,
        use_keyset_pagination: false,
        select_fewer_columns: false,
    };
    if row_limited {
        options.use_keyset_pagination = true;
        if input.max_rows < row_limit {
            options.suggested_max_rows = (input.max_rows.saturating_mul(2)).min(row_limit);
        }
    }
    if output.returned_bytes >= input.max_bytes || !output.truncated_columns.is_empty() {
        options.select_fewer_columns = true;
        options.suggested_shape = suggested_shape(&input.shape, &output.columns).to_owned();
        if input.max_bytes < byte_limit {
            options.suggested_max_bytes = input.max_bytes.saturating_mul(2).min(byte_limit);
        }
    }
    let mut hints = vec![
        "use GROUP BY/count/sum/min/max when you need a summary instead of raw rows".to_owned(),
    ];
    if row_limited {
        hints.insert(
            0,
            "result reached max_rows; narrow with a WHERE predicate when you need specific rows"
                .to_owned(),
        );
    }
    if options.select_fewer_columns {
        hints.push(
            "result reached max_bytes; retry with fewer SELECT columns or a narrower WHERE clause"
                .to_owned(),
        );
    }
    if !options.suggested_shape.is_empty() {
        hints.push(format!(
            "retry with shape={} to reduce repeated row keys when comparing many rows",
            options.suggested_shape
        ));
    }
    if options.use_keyset_pagination {
        hints.push("for raw row browsing, use ORDER BY on a stable key and continue with WHERE key > last_seen_key".to_owned());
    }
    output.more = Some(More { options, hints });
}

fn suggested_shape(current: &str, columns: &[Column]) -> &'static str {
    if current != SHAPE_ROWS {
        return "";
    }
    if columns.len() == 1 {
        SHAPE_VALUES
    } else if columns.len() > 1 {
        SHAPE_COLUMNS
    } else {
        ""
    }
}

fn encoded_len(output: &SqlQueryOutput) -> Result<usize> {
    serde_json::to_vec(output)
        .map(|bytes| bytes.len())
        .map_err(|error| Error::internal(format!("serialize sql query output: {error}")))
}

async fn validate_target_ips(endpoint: &str) -> Result<()> {
    let url = url::Url::parse(endpoint)
        .map_err(|error| Error::validation(format!("postgres endpoint: {error}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| Error::validation("postgres endpoint requires host"))?;
    let port = url.port_or_known_default().unwrap_or(5432);
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked_target_ip(ip) {
            return Err(Error::validation(
                "target IP is private/link-local/loopback",
            ));
        }
        return Ok(());
    }
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| Error::validation(format!("resolve target host: {error}")))?;
    let ips = addrs.map(|addr: SocketAddr| addr.ip()).collect::<Vec<_>>();
    if ips.is_empty() {
        return Err(Error::validation("resolve target host: no IPs"));
    }
    if ips.into_iter().any(is_blocked_target_ip) {
        return Err(Error::validation(
            "target IP is private/link-local/loopback",
        ));
    }
    Ok(())
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
            actor_role: Some(role_for_channel(self.caller.channel).to_owned()),
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
            shape: self.input.shape.clone(),
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
            error_message_safe: error_message.map(safe_history_message),
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
        let channel = channel_str(self.caller.channel).to_owned();
        let credential = self.credential.as_ref();
        let params = AuditLogParams {
            action: format!("{channel}.sql.query"),
            channel,
            outcome: outcome.to_owned(),
            severity: if outcome == "ok" { "info" } else { "warning" }.to_owned(),
            actor_user_id: Some(self.caller.user.id),
            actor_role: Some(role_for_channel(self.caller.channel).to_owned()),
            actor_ip: None,
            actor_user_agent: None,
            target_type: Some("credential".to_owned()),
            target_id: credential.map(|credential| credential.id.to_string()),
            target_key: Some(
                credential
                    .map(|credential| credential.alias.clone())
                    .unwrap_or_else(|| self.input.alias.clone()),
            ),
            request_id: self.caller.request_id.clone(),
            purpose: Some(self.input.purpose.clone()),
            detail: audit_detail(self.input, credential, outcome, error_kind, output),
        };
        if let Err(error) = self.audit.append(params).await {
            tracing::error!(event = "sql.query.audit_failed", detail = %error);
        }
    }
}

#[derive(Debug, Clone)]
struct CredentialSnapshot {
    id: Uuid,
    owner_user_id: Uuid,
    alias: String,
    category: CredentialCategory,
    provider: String,
    env: String,
}

impl From<&Credential> for CredentialSnapshot {
    fn from(credential: &Credential) -> Self {
        Self {
            id: credential.id,
            owner_user_id: credential.owner_user_id,
            alias: credential.alias.clone(),
            category: credential.category,
            provider: credential.provider.clone(),
            env: credential.env.clone(),
        }
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
    detail.insert("shape".to_owned(), serde_json::json!(input.shape));
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
    serde_json::json!(
        output
            .columns
            .iter()
            .map(|column| column.name.clone())
            .collect::<Vec<_>>()
    )
}

fn safe_history_message(value: &str) -> String {
    value.replace(['\r', '\n'], " ").chars().take(512).collect()
}

fn channel_str(channel: Channel) -> &'static str {
    match channel {
        Channel::Api => "api",
        Channel::Mcp | Channel::Browser => "mcp",
    }
}

fn role_for_channel(_channel: Channel) -> &'static str {
    "active"
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero_i32(value: &i32) -> bool {
    *value == 0
}

fn is_zero_usize(value: &usize) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use opsgate_domain::credential::CredentialPolicy;

    fn base_input() -> SqlQueryInput {
        SqlQueryInput {
            alias: "analytics".to_owned(),
            purpose: "Count recent rows".to_owned(),
            query: "select status, count(*) from payments group by status".to_owned(),
            params: Vec::new(),
            shape: String::new(),
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
        assert_eq!(input.shape, SHAPE_ROWS);
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
        input.shape = "wide".to_owned();
        assert!(normalize_input(input.clone()).is_err());
        input = base_input();
        input.max_rows = Some(MAX_MAX_ROWS + 1);
        assert!(normalize_input(input).is_err());
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
    fn shapes_and_budget_are_secret_free() -> Result<()> {
        let rows = vec![
            serde_json::json!({"status":"failed", "count": 42}),
            serde_json::json!({"status":"paid", "count": 900}),
        ];
        let mut output = build_output(rows, SHAPE_COLUMNS, false)?;
        let input = normalize_input(SqlQueryInput {
            shape: SHAPE_COLUMNS.to_owned(),
            max_bytes: Some(1024),
            ..base_input()
        })?;
        finalize_output(&mut output, &input, &CredentialPolicy::default())?;
        assert_eq!(output.row_count, 2);
        assert!(output.rows.is_empty());
        assert!(output.data.contains_key("status"));
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
        let output = build_output(rows, SHAPE_ROWS, false)?;
        let credential = CredentialSnapshot::from(&sql_credential(CredentialPolicy::default()));
        let detail = audit_detail(&input, Some(&credential), "ok", None, Some(&output));
        let serialized = detail.to_string();
        assert!(serialized.contains("query_sha256"));
        assert!(serialized.contains("result_columns"));
        assert!(!serialized.contains("select secret_col"));
        assert!(!serialized.contains("secret-param"));
        assert!(!serialized.contains("secret-value"));
        assert!(!serialized.contains("endpoint"));
        Ok(())
    }
}

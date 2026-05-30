use std::time::Instant;

use opsgate_core::validation::{trim_required, validate_purpose};
use opsgate_core::{Error, Result};
use opsgate_db::{AuditRepo, CredentialRepo};
use opsgate_domain::Caller;
use opsgate_domain::credential::{Credential, CredentialCategory};
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Connection, Executor, FromRow, PgConnection};

use crate::credential::snapshot::CredentialSnapshot;
use crate::sql_common::SqlSecret;

const DEFAULT_MODE: &str = "tables";
const MODE_TABLES: &str = "tables";
const MODE_TABLE: &str = "table";
const DEFAULT_NAMESPACE: &str = "public";
const DEFAULT_LIMIT: i32 = 50;
const MAX_LIMIT: i32 = 100;
const DEFAULT_MAX_BYTES: usize = 64 * 1024;
const MIN_MAX_BYTES: usize = 1024;
const MAX_MAX_BYTES: usize = 1024 * 1024;
const DEFAULT_TIMEOUT_MS: u32 = 3000;
const MAX_TIMEOUT_MS: u32 = 30000;
const MAX_IDENT_LEN: usize = 128;
#[derive(Clone)]
pub struct SqlSchemaService {
    credentials: CredentialRepo,
    audit: AuditRepo,
    sealer: opsgate_core::crypto::Sealer,
}

impl SqlSchemaService {
    pub fn new(
        credentials: CredentialRepo,
        audit: AuditRepo,
        sealer: opsgate_core::crypto::Sealer,
    ) -> Self {
        Self {
            credentials,
            audit,
            sealer,
        }
    }

    pub async fn execute(&self, caller: &Caller, input: SqlSchemaInput) -> Result<SqlSchemaOutput> {
        let raw_alias = crate::audit::safe::message(&input.alias);
        let input = match normalize_input(input) {
            Ok(input) => input,
            Err(error) => {
                self.record_pre_input_denial(caller, &raw_alias, "bad_input", &error)
                    .await;
                return Err(error);
            }
        };
        let mut recorder = SchemaRecorder::new(&self.audit, caller, &input);

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
        if let Err(error) = validate_policy(&credential, &input) {
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
        let mut output = match execute_schema_query(&target, &secret, &input).await {
            Ok(output) => output,
            Err(error) => {
                recorder
                    .err("schema_lookup_failed", "sql schema lookup failed")
                    .await;
                return Err(error);
            }
        };
        output.latency_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        finalize_output(&mut output, &input)?;
        recorder.ok(&output).await;
        Ok(output)
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
            pre_input_denial_audit_event(caller, alias, reason, error),
            "sql.schema.audit_failed",
        )
        .await;
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SqlSchemaInput {
    pub alias: String,
    pub purpose: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub table: String,
    pub limit: Option<i32>,
    #[serde(default)]
    pub cursor: String,
    pub max_bytes: Option<usize>,
    pub timeout_ms: Option<u32>,
    #[serde(default)]
    pub include_indexes: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SqlSchemaOutput {
    pub mode: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tables: Vec<TableSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<TableDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<Page>,
    pub truncated: bool,
    pub returned_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub more: Option<More>,
    pub latency_ms: i64,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct TableSummary {
    pub namespace: String,
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct TableDetail {
    pub namespace: String,
    pub name: String,
    pub kind: String,
    pub columns: Vec<Column>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub primary_key: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub indexes: Vec<Index>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Column {
    pub name: String,
    #[serde(rename = "type")]
    pub data_type: String,
    pub nullable: bool,
    #[serde(skip_serializing_if = "is_false", default)]
    pub has_default: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Index {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
    #[serde(skip_serializing_if = "is_false", default)]
    pub primary: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Page {
    pub limit: i32,
    pub returned: usize,
    pub has_more: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub next_cursor: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct More {
    pub options: MoreOption,
    pub hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct MoreOption {
    #[serde(skip_serializing_if = "is_false", default)]
    pub retry_without_indexes: bool,
    #[serde(skip_serializing_if = "is_false", default)]
    pub use_table_mode: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_max_bytes: Option<usize>,
}

#[derive(Debug, Clone)]
struct NormalizedInput {
    alias: String,
    purpose: String,
    mode: String,
    namespace: String,
    table: String,
    limit: i32,
    cursor: String,
    max_bytes: usize,
    timeout_ms: u32,
    include_indexes: bool,
}

fn normalize_input(input: SqlSchemaInput) -> Result<NormalizedInput> {
    let alias = trim_required("alias", &input.alias)?;
    let purpose = validate_purpose(&input.purpose)?;
    let mode = if input.mode.trim().is_empty() {
        DEFAULT_MODE.to_owned()
    } else {
        input.mode.trim().to_ascii_lowercase()
    };
    if !matches!(mode.as_str(), MODE_TABLES | MODE_TABLE) {
        return Err(Error::validation("mode must be tables or table"));
    }
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(Error::validation("limit out of range"));
    }
    let max_bytes = input.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    if !(MIN_MAX_BYTES..=MAX_MAX_BYTES).contains(&max_bytes) {
        return Err(Error::validation("max_bytes out of range"));
    }
    let timeout_ms = input.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(Error::validation("timeout_ms out of range"));
    }
    let cursor = input.cursor.trim().to_owned();
    if cursor.contains(['\0', '\r', '\n']) {
        return Err(Error::validation("cursor must not contain NUL or CR/LF"));
    }
    let mut namespace = input.namespace.trim().to_owned();
    let mut table = input.table.trim().to_owned();
    if mode == MODE_TABLE {
        if namespace.is_empty() {
            namespace = DEFAULT_NAMESPACE.to_owned();
        }
        if table.contains('.') && namespace == DEFAULT_NAMESPACE {
            let mut parts = table.splitn(2, '.');
            namespace = parts.next().unwrap_or_default().trim().to_owned();
            table = parts.next().unwrap_or_default().trim().to_owned();
        }
        validate_identifier("namespace", &namespace)?;
        validate_identifier("table", &table)?;
    }
    Ok(NormalizedInput {
        alias,
        purpose,
        mode,
        namespace,
        table,
        limit,
        cursor,
        max_bytes,
        timeout_ms,
        include_indexes: input.include_indexes,
    })
}

fn validate_identifier(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_IDENT_LEN || value.contains(['\0', '\r', '\n']) {
        return Err(Error::validation(format!(
            "{name} must be 1-{MAX_IDENT_LEN} characters without NUL or CR/LF"
        )));
    }
    Ok(())
}

fn validate_policy(credential: &Credential, input: &NormalizedInput) -> Result<()> {
    let policy = &credential.policy;
    if policy.allow_explain_analyze && !policy.allow_explain {
        return Err(Error::validation("sql policy is invalid"));
    }
    if policy.max_rows > 0
        && input.mode == MODE_TABLES
        && input.limit > i32::try_from(policy.max_rows).unwrap_or(i32::MAX)
    {
        return Err(Error::validation("limit exceeds credential policy"));
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

async fn execute_schema_query(
    target: &crate::target::postgres::GuardedPostgresTarget,
    secret: &SqlSecret,
    input: &NormalizedInput,
) -> Result<SqlSchemaOutput> {
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
    let result = if input.mode == MODE_TABLE {
        load_table(&mut conn, input).await
    } else {
        list_tables(&mut conn, input).await
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

async fn list_tables(conn: &mut PgConnection, input: &NormalizedInput) -> Result<SqlSchemaOutput> {
    let (cursor_ns, cursor_table) = split_cursor(&input.cursor);
    let rows = sqlx::query_as::<_, TableRow>(
        r#"
        SELECT table_schema AS namespace, table_name AS name, table_type
        FROM information_schema.tables
        WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
          AND table_type IN ('BASE TABLE', 'VIEW')
          AND (($1 = '' AND $2 = '') OR (table_schema, table_name) > ($1, $2))
        ORDER BY table_schema, table_name
        LIMIT $3
        "#,
    )
    .bind(cursor_ns)
    .bind(cursor_table)
    .bind(input.limit + 1)
    .fetch_all(conn)
    .await
    .map_err(|_error| Error::internal("postgres schema table list failed"))?;

    let mut tables = Vec::new();
    let mut page = Page {
        limit: input.limit,
        returned: 0,
        has_more: false,
        next_cursor: String::new(),
    };
    for row in rows {
        if tables.len() >= usize::try_from(input.limit).unwrap_or(usize::MAX) {
            page.has_more = true;
            continue;
        }
        page.next_cursor = join_cursor(&row.namespace, &row.name);
        tables.push(TableSummary {
            namespace: row.namespace,
            name: row.name,
            kind: table_kind(&row.table_type).to_owned(),
        });
    }
    page.returned = tables.len();
    if !page.has_more {
        page.next_cursor.clear();
    }
    Ok(SqlSchemaOutput {
        mode: MODE_TABLES.to_owned(),
        tables,
        table: None,
        page: Some(page),
        truncated: false,
        returned_bytes: 0,
        more: None,
        latency_ms: 0,
    })
}

async fn load_table(conn: &mut PgConnection, input: &NormalizedInput) -> Result<SqlSchemaOutput> {
    let (columns, kind) = load_columns(conn, &input.namespace, &input.table).await?;
    let mut detail = TableDetail {
        namespace: input.namespace.clone(),
        name: input.table.clone(),
        kind,
        columns,
        primary_key: load_primary_key(conn, &input.namespace, &input.table).await?,
        indexes: Vec::new(),
    };
    if detail.columns.is_empty() {
        return Err(Error::not_found(
            "table not found or has no visible columns",
        ));
    }
    if input.include_indexes {
        detail.indexes = load_indexes(conn, &input.namespace, &input.table).await?;
    }
    Ok(SqlSchemaOutput {
        mode: MODE_TABLE.to_owned(),
        tables: Vec::new(),
        table: Some(detail),
        page: None,
        truncated: false,
        returned_bytes: 0,
        more: None,
        latency_ms: 0,
    })
}

async fn load_columns(
    conn: &mut PgConnection,
    namespace: &str,
    table: &str,
) -> Result<(Vec<Column>, String)> {
    let rows = sqlx::query_as::<_, ColumnRow>(
        r#"
        SELECT a.attname AS name,
               pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
               NOT a.attnotnull AS nullable,
               ad.oid IS NOT NULL AS has_default,
               c.relkind::text AS relation_kind
        FROM pg_catalog.pg_attribute a
        JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        WHERE n.nspname = $1
          AND c.relname = $2
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND a.attnum > 0
          AND NOT a.attisdropped
        ORDER BY a.attnum
        "#,
    )
    .bind(namespace)
    .bind(table)
    .fetch_all(conn)
    .await
    .map_err(|_error| Error::internal("postgres schema column lookup failed"))?;
    let mut kind = "table".to_owned();
    let columns = rows
        .into_iter()
        .map(|row| {
            kind = relation_kind(&row.relation_kind).to_owned();
            Column {
                name: row.name,
                data_type: row.data_type,
                nullable: row.nullable,
                has_default: row.has_default,
            }
        })
        .collect();
    Ok((columns, kind))
}

async fn load_primary_key(
    conn: &mut PgConnection,
    namespace: &str,
    table: &str,
) -> Result<Vec<String>> {
    let joined = sqlx::query_scalar::<_, String>(
        r#"
        SELECT COALESCE(array_to_string(array_agg(a.attname ORDER BY ord.n), ','), '')
        FROM pg_catalog.pg_class t
        JOIN pg_catalog.pg_namespace ns ON ns.oid = t.relnamespace
        JOIN pg_catalog.pg_index ix ON ix.indrelid = t.oid AND ix.indisprimary
        JOIN unnest(ix.indkey) WITH ORDINALITY AS ord(attnum, n) ON true
        JOIN pg_catalog.pg_attribute a ON a.attrelid = t.oid AND a.attnum = ord.attnum
        WHERE ns.nspname = $1 AND t.relname = $2
        "#,
    )
    .bind(namespace)
    .bind(table)
    .fetch_one(conn)
    .await
    .map_err(|_error| Error::internal("postgres schema primary key lookup failed"))?;
    Ok(split_comma_list(&joined))
}

async fn load_indexes(conn: &mut PgConnection, namespace: &str, table: &str) -> Result<Vec<Index>> {
    let rows = sqlx::query_as::<_, IndexRow>(
        r#"
        SELECT ci.relname AS name,
               ix.indisunique AS unique,
               ix.indisprimary AS primary,
               COALESCE(array_to_string(array_agg(a.attname ORDER BY ord.n) FILTER (WHERE a.attname IS NOT NULL), ','), '') AS columns
        FROM pg_catalog.pg_class t
        JOIN pg_catalog.pg_namespace ns ON ns.oid = t.relnamespace
        JOIN pg_catalog.pg_index ix ON ix.indrelid = t.oid
        JOIN pg_catalog.pg_class ci ON ci.oid = ix.indexrelid
        JOIN unnest(ix.indkey) WITH ORDINALITY AS ord(attnum, n) ON true
        LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = t.oid AND a.attnum = ord.attnum
        WHERE ns.nspname = $1 AND t.relname = $2
        GROUP BY ci.relname, ix.indisunique, ix.indisprimary
        ORDER BY ix.indisprimary DESC, ci.relname
        "#,
    )
    .bind(namespace)
    .bind(table)
    .fetch_all(conn)
    .await
    .map_err(|_error| Error::internal("postgres schema index lookup failed"))?;
    Ok(rows
        .into_iter()
        .map(|row| Index {
            name: row.name,
            columns: split_comma_list(&row.columns),
            unique: row.unique,
            primary: row.primary,
        })
        .collect())
}

fn finalize_output(out: &mut SqlSchemaOutput, input: &NormalizedInput) -> Result<()> {
    out.returned_bytes = encoded_len(out)?;
    if out.returned_bytes <= input.max_bytes {
        return Ok(());
    }
    out.truncated = true;
    trim_schema_payload(out, input.max_bytes)?;
    if input.max_bytes < MAX_MAX_BYTES {
        out.more = Some(More {
            options: MoreOption {
                retry_without_indexes: true,
                use_table_mode: out.mode == MODE_TABLES,
                suggested_max_bytes: Some((input.max_bytes * 2).min(MAX_MAX_BYTES)),
            },
            hints: vec![
                "schema output exceeded max_bytes; retry mode=table for one table or increase max_bytes if policy allows it".to_owned(),
                "indexes are omitted first when table detail is too large".to_owned(),
            ],
        });
    }
    out.returned_bytes = encoded_len(out)?;
    if out.returned_bytes > input.max_bytes {
        out.more = None;
        trim_schema_payload(out, input.max_bytes)?;
        out.returned_bytes = encoded_len(out)?;
    }
    Ok(())
}

fn trim_schema_payload(out: &mut SqlSchemaOutput, max_bytes: usize) -> Result<()> {
    trim_table_detail(out, max_bytes)?;
    trim_table_list(out, max_bytes)
}

fn trim_table_detail(out: &mut SqlSchemaOutput, max_bytes: usize) -> Result<()> {
    while out.returned_bytes > max_bytes {
        let Some(table) = &mut out.table else {
            return Ok(());
        };
        if !table.indexes.is_empty() {
            table.indexes.clear();
        } else if !table.primary_key.is_empty() {
            table.primary_key.clear();
        } else if !table.columns.is_empty() {
            table.columns.pop();
        } else {
            return Ok(());
        }
        out.returned_bytes = encoded_len(out)?;
    }
    Ok(())
}

fn trim_table_list(out: &mut SqlSchemaOutput, max_bytes: usize) -> Result<()> {
    while out.returned_bytes > max_bytes && !out.tables.is_empty() {
        out.tables.pop();
        if let Some(page) = &mut out.page {
            page.has_more = true;
            page.returned = out.tables.len();
            page.next_cursor = out
                .tables
                .last()
                .map(|table| join_cursor(&table.namespace, &table.name))
                .unwrap_or_default();
        }
        out.returned_bytes = encoded_len(out)?;
    }
    Ok(())
}

fn encoded_len(out: &SqlSchemaOutput) -> Result<usize> {
    serde_json::to_vec(out)
        .map(|bytes| bytes.len())
        .map_err(|error| Error::internal(format!("serialize sql schema output: {error}")))
}

#[derive(Debug, FromRow)]
struct TableRow {
    namespace: String,
    name: String,
    table_type: String,
}

#[derive(Debug, FromRow)]
struct ColumnRow {
    name: String,
    data_type: String,
    nullable: bool,
    has_default: bool,
    relation_kind: String,
}

#[derive(Debug, FromRow)]
struct IndexRow {
    name: String,
    unique: bool,
    primary: bool,
    columns: String,
}

fn split_cursor(cursor: &str) -> (String, String) {
    if let Some((namespace, table)) = cursor.split_once('.') {
        return (namespace.to_owned(), table.to_owned());
    }
    (String::new(), cursor.to_owned())
}

fn join_cursor(namespace: &str, table: &str) -> String {
    format!("{namespace}.{table}")
}

fn table_kind(table_type: &str) -> &'static str {
    if table_type.trim().eq_ignore_ascii_case("VIEW") {
        "view"
    } else {
        "table"
    }
}

fn relation_kind(kind: &str) -> &'static str {
    match kind {
        "v" => "view",
        "m" => "materialized_view",
        "f" => "foreign_table",
        "p" => "partitioned_table",
        _ => "table",
    }
}

fn split_comma_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn is_false(value: &bool) -> bool {
    !*value
}

struct SchemaRecorder<'a> {
    audit: &'a AuditRepo,
    caller: &'a Caller,
    input: &'a NormalizedInput,
    credential: Option<CredentialSnapshot>,
}

impl<'a> SchemaRecorder<'a> {
    fn new(audit: &'a AuditRepo, caller: &'a Caller, input: &'a NormalizedInput) -> Self {
        Self {
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

    async fn ok(&self, output: &SqlSchemaOutput) {
        self.record("ok", None, None, Some(output)).await;
    }

    async fn record(
        &self,
        outcome: &str,
        error_kind: Option<&str>,
        error_message: Option<&str>,
        output: Option<&SqlSchemaOutput>,
    ) {
        let credential = self.credential.as_ref();
        let event = crate::audit::runtime::tool_event(
            self.caller,
            "sql.schema",
            outcome,
            credential.map(|credential| credential.id.to_string()),
            credential
                .map(|credential| credential.alias.clone())
                .unwrap_or_else(|| self.input.alias.clone()),
            Some(self.input.purpose.clone()),
            audit_detail(
                self.input,
                credential,
                outcome,
                error_kind,
                error_message,
                output,
            ),
        );
        crate::audit::append_event(self.audit, event, "sql.schema.audit_failed").await;
    }
}

fn audit_detail(
    input: &NormalizedInput,
    credential: Option<&CredentialSnapshot>,
    outcome: &str,
    error_kind: Option<&str>,
    error_message: Option<&str>,
    output: Option<&SqlSchemaOutput>,
) -> Value {
    let mut detail = serde_json::Map::new();
    detail.insert("schema_version".to_owned(), serde_json::json!(1));
    detail.insert("mode".to_owned(), serde_json::json!(input.mode));
    detail.insert("namespace".to_owned(), serde_json::json!(input.namespace));
    detail.insert("table".to_owned(), serde_json::json!(input.table));
    detail.insert("limit".to_owned(), serde_json::json!(input.limit));
    detail.insert("max_bytes".to_owned(), serde_json::json!(input.max_bytes));
    detail.insert("timeout_ms".to_owned(), serde_json::json!(input.timeout_ms));
    detail.insert(
        "include_indexes".to_owned(),
        serde_json::json!(input.include_indexes),
    );
    detail.insert("purpose".to_owned(), serde_json::json!(input.purpose));
    if let Some(error_kind) = error_kind {
        let key = if outcome == "denied" {
            "denial_reason"
        } else {
            "error_kind"
        };
        detail.insert(key.to_owned(), serde_json::json!(error_kind));
    }
    if let Some(message) = error_message {
        detail.insert(
            "error_message_safe".to_owned(),
            serde_json::json!(crate::audit::safe::message(message)),
        );
    }
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
    if let Some(output) = output {
        detail.insert(
            "returned_bytes".to_owned(),
            serde_json::json!(output.returned_bytes),
        );
        detail.insert(
            "latency_ms".to_owned(),
            serde_json::json!(output.latency_ms),
        );
        detail.insert("truncated".to_owned(), serde_json::json!(output.truncated));
        if let Some(page) = &output.page {
            detail.insert("returned".to_owned(), serde_json::json!(page.returned));
            detail.insert("has_more".to_owned(), serde_json::json!(page.has_more));
        }
        if let Some(table) = &output.table {
            detail.insert(
                "column_count".to_owned(),
                serde_json::json!(table.columns.len()),
            );
            detail.insert(
                "index_count".to_owned(),
                serde_json::json!(table.indexes.len()),
            );
        }
    }
    Value::Object(detail)
}

fn pre_input_denial_audit_event(
    caller: &Caller,
    alias: &str,
    reason: &str,
    error: &Error,
) -> crate::audit::AuditEvent {
    crate::audit::runtime::pre_input_denial_event(
        caller,
        "sql.schema",
        alias,
        reason,
        Some((
            "error_message_safe",
            serde_json::json!(crate::audit::safe::message(&error.to_string())),
        )),
    )
}

#[cfg(test)]
mod tests {

    use super::*;

    fn base_input() -> SqlSchemaInput {
        SqlSchemaInput {
            alias: "analytics".to_owned(),
            purpose: "Inspect schema safely".to_owned(),
            mode: String::new(),
            namespace: String::new(),
            table: String::new(),
            limit: None,
            cursor: String::new(),
            max_bytes: None,
            timeout_ms: None,
            include_indexes: false,
        }
    }

    #[test]
    fn input_defaults_match_docs() -> Result<()> {
        let input = normalize_input(base_input())?;
        assert_eq!(input.mode, MODE_TABLES);
        assert_eq!(input.limit, DEFAULT_LIMIT);
        assert_eq!(input.max_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(input.timeout_ms, DEFAULT_TIMEOUT_MS);
        Ok(())
    }

    #[test]
    fn table_mode_normalizes_namespace_and_rejects_bad_identifier() -> Result<()> {
        let input = normalize_input(SqlSchemaInput {
            mode: "table".to_owned(),
            table: "public.api_call_history".to_owned(),
            ..base_input()
        })?;
        assert_eq!(input.namespace, "public");
        assert_eq!(input.table, "api_call_history");

        let bad = normalize_input(SqlSchemaInput {
            mode: "table".to_owned(),
            table: "bad\nname".to_owned(),
            ..base_input()
        });
        assert!(bad.is_err());
        Ok(())
    }

    #[test]
    fn audit_detail_is_secret_free_and_uses_specific_reason_keys() -> Result<()> {
        let input = normalize_input(SqlSchemaInput {
            mode: "table".to_owned(),
            table: "audit_logs".to_owned(),
            ..base_input()
        })?;
        let detail = audit_detail(
            &input,
            None,
            "denied",
            Some("policy_denied"),
            Some("bad\nmessage secret"),
            None,
        );
        let serialized = detail.to_string();
        assert!(serialized.contains("denial_reason"));
        assert!(serialized.contains("error_message_safe"));
        assert!(!serialized.contains("\n"));
        assert!(!serialized.contains("endpoint"));
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("\"reason\""));
        Ok(())
    }
}

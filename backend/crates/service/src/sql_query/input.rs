use crate::llm_output::validate_json_paths;
use opsgate_core::validation::{trim_required, validate_purpose};
use opsgate_core::{Error, Result};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const DEFAULT_MAX_ROWS: i32 = 100;
const MAX_MAX_ROWS: i32 = 1000;
const DEFAULT_MAX_BYTES: usize = 64 * 1024;
const MIN_MAX_BYTES: usize = 1024;
pub(super) const MAX_MAX_BYTES: usize = 1024 * 1024;
const DEFAULT_TIMEOUT_MS: u32 = 3000;
const MAX_TIMEOUT_MS: u32 = 30000;
const MAX_QUERY_LEN: usize = 16_000;
const MAX_PARAMS: usize = 64;

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SqlQueryInput {
    /// Alias from credential_list with category=sql and provider=postgres.
    pub alias: String,
    /// Short human reason for the query; stored in audit/history.
    pub purpose: String,
    /// Optional database on the same registered Postgres server. Defaults to the credential database.
    #[serde(default)]
    pub database: Option<String>,
    /// Read-only SQL. Only SELECT/WITH are allowed. Prefer explicit columns, WHERE, count/group, or keyset pagination; avoid SELECT *.
    pub query: String,
    /// Positional bind parameters for the SQL query.
    #[serde(default)]
    #[schemars(schema_with = "opsgate_core::schema::json_value_array_schema")]
    pub params: Vec<Value>,
    /// JSONPath projections over column arrays. Use RFC 9535 syntax; regex filters use search(value, pattern) or match(value, pattern). For row counts, use row_count or $.column.length().
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
    pub(super) database: Option<String>,
    pub(super) query: String,
    pub(super) params: Vec<Value>,
    pub(super) jsonpath: Vec<String>,
    pub(super) max_rows: i32,
    pub(super) max_bytes: usize,
    pub(super) timeout_ms: u32,
    pub(super) query_sha256: String,
}

pub(super) fn normalize_input(input: SqlQueryInput) -> Result<NormalizedInput> {
    let alias = trim_required("alias", &input.alias)?;
    let purpose = validate_purpose(&input.purpose)?;
    let database = crate::sql_common::normalize_database_name(input.database)?;
    let query = input.query.trim().trim_end_matches(';').trim().to_owned();
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
        database,
        query,
        params: input.params,
        jsonpath: input.jsonpath,
        max_rows,
        max_bytes,
        timeout_ms,
        query_sha256,
    })
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> SqlQueryInput {
        SqlQueryInput {
            alias: "analytics".to_owned(),
            purpose: "Count recent rows".to_owned(),
            query: "select status, count(*) from payments group by status".to_owned(),
            database: None,
            params: Vec::new(),
            jsonpath: Vec::new(),
            max_rows: None,
            max_bytes: None,
            timeout_ms: None,
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
    fn input_normalizes_optional_database() -> Result<()> {
        let input = normalize_input(SqlQueryInput {
            database: Some(" feedgate_1 ".to_owned()),
            ..base_input()
        })?;
        assert_eq!(input.database.as_deref(), Some("feedgate_1"));

        let bad = normalize_input(SqlQueryInput {
            database: Some("bad/database".to_owned()),
            ..base_input()
        });
        assert!(bad.is_err());
        Ok(())
    }

    #[test]
    fn input_normalizes_trailing_statement_semicolon() -> Result<()> {
        let input = normalize_input(SqlQueryInput {
            query: " select 1; ".to_owned(),
            ..base_input()
        })?;

        assert_eq!(input.query, "select 1");
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
}

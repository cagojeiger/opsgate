use opsgate_core::validation::{trim_required, validate_max_bytes, validate_purpose};
use opsgate_core::{Error, Result};
use schemars::JsonSchema;
use serde::Deserialize;

const DEFAULT_MODE: &str = "tables";
pub(super) const MODE_TABLES: &str = "tables";
pub(super) const MODE_TABLE: &str = "table";
const DEFAULT_NAMESPACE: &str = "public";
const DEFAULT_LIMIT: i32 = 50;
const MAX_LIMIT: i32 = 100;
const DEFAULT_MAX_BYTES: usize = 64 * 1024;
const MIN_MAX_BYTES: usize = 1024;
pub(super) const MAX_MAX_BYTES: usize = 1024 * 1024;
const DEFAULT_TIMEOUT_MS: u32 = 3000;
const MAX_TIMEOUT_MS: u32 = 30000;
const MAX_IDENT_LEN: usize = 128;

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SqlSchemaInput {
    /// Alias from credential_list with category=sql and provider=postgres.
    pub alias: String,
    /// Short human reason for inspecting schema; stored in audit/history.
    pub purpose: String,
    /// Optional database on the same registered Postgres server. Defaults to the credential database.
    #[serde(default)]
    pub database: Option<String>,
    /// tables = list tables. table = inspect one table using namespace and table.
    #[serde(default)]
    pub mode: String,
    /// Schema/namespace for mode=table, usually public.
    #[serde(default)]
    pub namespace: String,
    /// Table name for mode=table.
    #[serde(default)]
    pub table: String,
    /// Maximum tables returned in mode=tables.
    pub limit: Option<i32>,
    /// Pagination cursor returned by a previous mode=tables response.
    #[serde(default)]
    pub cursor: String,
    /// Response byte budget. If too small, retry with mode=table for one table.
    pub max_bytes: Option<usize>,
    /// Schema query timeout in milliseconds, bounded by credential policy.
    pub timeout_ms: Option<u32>,
    /// Include indexes in mode=table output.
    #[serde(default)]
    pub include_indexes: bool,
}

#[derive(Debug, Clone)]
pub(super) struct NormalizedInput {
    pub(super) alias: String,
    pub(super) purpose: String,
    pub(super) database: Option<String>,
    pub(super) mode: String,
    pub(super) namespace: String,
    pub(super) table: String,
    pub(super) limit: i32,
    pub(super) cursor: String,
    pub(super) max_bytes: usize,
    pub(super) timeout_ms: u32,
    pub(super) include_indexes: bool,
}

pub(super) fn normalize_input(input: SqlSchemaInput) -> Result<NormalizedInput> {
    let alias = trim_required("alias", &input.alias)?;
    let purpose = validate_purpose(&input.purpose)?;
    let database = crate::sql_common::normalize_database_name(input.database)?;
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
    let max_bytes = validate_max_bytes(
        input.max_bytes,
        DEFAULT_MAX_BYTES,
        MIN_MAX_BYTES,
        MAX_MAX_BYTES,
    )?;
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
        database,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> SqlSchemaInput {
        SqlSchemaInput {
            alias: "analytics".to_owned(),
            purpose: "Inspect schema safely".to_owned(),
            database: None,
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
    fn input_normalizes_optional_database() -> Result<()> {
        let input = normalize_input(SqlSchemaInput {
            database: Some(" authgate ".to_owned()),
            ..base_input()
        })?;
        assert_eq!(input.database.as_deref(), Some("authgate"));

        let bad = normalize_input(SqlSchemaInput {
            database: Some("bad/database".to_owned()),
            ..base_input()
        });
        assert!(bad.is_err());
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
    fn max_bytes_error_includes_allowed_range() {
        let mut input = base_input();
        input.max_bytes = Some(MIN_MAX_BYTES - 1);
        let msg = normalize_input(input)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();

        assert!(msg.contains("max_bytes"));
        assert!(msg.contains(&MIN_MAX_BYTES.to_string()));
        assert!(msg.contains(&MAX_MAX_BYTES.to_string()));
    }
}

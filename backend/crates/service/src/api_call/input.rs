use std::collections::BTreeMap;

use crate::llm_output::{TableProjection, validate_json_paths, validate_table_projection};
use opsgate_core::validation::{
    reject_crlf, trim_required, validate_count, validate_http_header_name,
    validate_http_header_value, validate_http_path, validate_max_bytes, validate_purpose,
    validate_text_len,
};
use opsgate_core::{Error, Result};
use reqwest::header::HeaderName;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

const DEFAULT_METHOD: &str = "GET";
const DEFAULT_MAX_BYTES: usize = 4096;
const MIN_MAX_BYTES: usize = 256;
pub(super) const MAX_MAX_BYTES: usize = 1024 * 1024;
const MAX_QUERY_KEYS: usize = 32;
const MAX_QUERY_KEY_LEN: usize = 128;
const MAX_QUERY_VALUE_LEN: usize = 4096;
const MAX_HEADERS: usize = 16;
const MAX_HEADER_NAME_LEN: usize = 128;
const MAX_HEADER_VALUE_LEN: usize = 1024;
const MAX_TABLE_COLUMN_NAME_LEN: usize = 128;

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ApiCallInput {
    /// Alias from credential_list with category=http.
    pub alias: String,
    /// Short human reason for the call; stored in audit/history.
    pub purpose: String,
    /// HTTP method. Defaults to GET and must be allowed by the credential policy.
    #[serde(default)]
    pub method: String,
    /// Absolute path for this call, appended after the hidden origin/base_path.
    /// Example: /api/v1/pods. Do not include scheme, host, or base_path here.
    pub request_path: String,
    /// Query string key/value pairs for this call. Policy may deny specific keys.
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    /// Extra request headers allowed by policy. Authorization and other secret/unsafe headers are blocked.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Optional JSON request body for methods that allow a body.
    #[serde(default)]
    #[schemars(schema_with = "opsgate_core::schema::optional_json_value_schema")]
    pub body: Option<Value>,
    /// Content-Type for body. Defaults to application/json when body is present.
    #[serde(default)]
    pub content_type: String,
    /// JSONPath projections returning one array per path (columnar). Use RFC 9535 syntax; regex filters use search(value, pattern) for partial search or match(value, pattern) for full-string match. length()/count() suffixes are supported. Mutually exclusive with table.
    #[serde(default)]
    pub jsonpath: Vec<String>,
    /// Build a table from the HTTP response: base enumerates the rows, columns maps each output column name to an RFC 9535 path evaluated relative to a single row (its $ is the row). Returns an array of one object per row, like SQL JSON_TABLE. Missing columns become null. Mutually exclusive with jsonpath. Prefer this over jsonpath when you need several columns aligned per item.
    #[serde(default)]
    pub table: Option<TableInput>,
    /// Response byte budget after JSONPath projection. Lower values force concise output.
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct TableInput {
    /// RFC 9535 path that enumerates the rows, e.g. $.items[*].
    pub base: String,
    /// Column name -> RFC 9535 path evaluated relative to each row (its $ is the row node), e.g. {"name": "$.metadata.name", "phase": "$.status.phase"}.
    pub columns: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub(super) struct NormalizedApiCallInput {
    pub(super) alias: String,
    pub(super) purpose: String,
    pub(super) method: String,
    pub(super) request_path: String,
    pub(super) query: BTreeMap<String, String>,
    pub(super) headers: BTreeMap<String, String>,
    pub(super) body: Option<Value>,
    pub(super) content_type: Option<String>,
    pub(super) jsonpath: Vec<String>,
    pub(super) table: Option<TableProjection>,
    pub(super) max_bytes: usize,
}

pub(super) fn normalize_input(input: ApiCallInput) -> Result<NormalizedApiCallInput> {
    let alias = trim_required("alias", &input.alias)?;
    let purpose = validate_purpose(&input.purpose)?;
    let method = if input.method.trim().is_empty() {
        DEFAULT_METHOD.to_owned()
    } else {
        input.method.trim().to_ascii_uppercase()
    };
    if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
        return Err(Error::validation("unsupported method"));
    }
    if method == "GET" && input.body.is_some() {
        return Err(Error::validation("GET must not carry a body"));
    }
    let request_path = validate_http_path(&input.request_path)?;
    let max_bytes = validate_max_bytes(
        input.max_bytes,
        DEFAULT_MAX_BYTES,
        MIN_MAX_BYTES,
        MAX_MAX_BYTES,
    )?;
    validate_json_paths(&input.jsonpath)?;
    let table = match input.table {
        Some(table) => {
            if !input.jsonpath.is_empty() {
                return Err(Error::validation(
                    "jsonpath and table are mutually exclusive",
                ));
            }
            let mut columns = BTreeMap::new();
            for (name, path) in table.columns {
                // Field names are recorded into audit detail, so they pass the
                // same hygiene gate as query keys (non-empty, bounded, no CR/LF/NUL).
                let column = trim_required("table column name", &name)?;
                reject_crlf("table column name", &column)?;
                validate_text_len("table column name", &column, 1, MAX_TABLE_COLUMN_NAME_LEN)?;
                if column.contains('\0') {
                    return Err(Error::validation("table column name must not contain NUL"));
                }
                if columns.contains_key(&column) {
                    return Err(Error::validation(
                        "duplicate table column name after trimming",
                    ));
                }
                columns.insert(column, path.trim().to_owned());
            }
            let table = TableProjection {
                base: table.base.trim().to_owned(),
                columns,
            };
            validate_table_projection(&table)?;
            Some(table)
        }
        None => None,
    };
    let query = normalize_query(input.query)?;
    validate_count("headers", input.headers.len(), MAX_HEADERS)?;
    let mut headers = BTreeMap::new();
    for (name, value) in input.headers {
        let name = validate_http_header_name(&name, MAX_HEADER_NAME_LEN)?;
        let value = validate_http_header_value(&value, MAX_HEADER_VALUE_LEN)?;
        if name.eq_ignore_ascii_case("accept") && !value.to_ascii_lowercase().contains("json") {
            return Err(Error::validation("header Accept must request JSON"));
        }
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_error| Error::validation("invalid header name"))?
                .to_string(),
            value,
        );
    }
    let content_type = if input.content_type.trim().is_empty() {
        None
    } else {
        Some(input.content_type.trim().to_owned())
    };
    if let Some(content_type) = &content_type {
        validate_http_header_value(content_type, MAX_HEADER_VALUE_LEN)?;
        if input.body.is_some() && !content_type.to_ascii_lowercase().contains("json") {
            return Err(Error::validation("content_type must describe JSON"));
        }
    }
    let mut jsonpath = input.jsonpath;
    for path in &mut jsonpath {
        *path = path.trim().to_owned();
    }
    Ok(NormalizedApiCallInput {
        alias,
        purpose,
        method,
        request_path,
        query,
        headers,
        body: input.body,
        content_type,
        jsonpath,
        table,
        max_bytes,
    })
}

fn normalize_query(query: BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
    validate_count("query", query.len(), MAX_QUERY_KEYS)?;
    let mut normalized = BTreeMap::new();
    for (key, value) in query {
        let key = trim_required("query key", &key)?;
        reject_crlf("query key", &key)?;
        validate_text_len("query key", &key, 1, MAX_QUERY_KEY_LEN)?;
        if key.contains('\0') {
            return Err(Error::validation("query key must not contain NUL"));
        }
        reject_crlf("query value", &value)?;
        validate_text_len("query value", &value, 0, MAX_QUERY_VALUE_LEN)?;
        if value.contains('\0') {
            return Err(Error::validation("query value must not contain NUL"));
        }
        normalized.insert(key, value);
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> ApiCallInput {
        ApiCallInput {
            alias: "prod".to_owned(),
            purpose: "Check pod phases".to_owned(),
            method: "GET".to_owned(),
            request_path: "/api/v1/pods".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: None,
            content_type: String::new(),
            jsonpath: Vec::new(),
            table: None,
            max_bytes: Some(4096),
        }
    }

    #[test]
    fn input_validation_matches_docs_boundary() {
        assert!(
            normalize_input(ApiCallInput {
                jsonpath: vec!["$.items[*].metadata.name".to_owned()],
                ..base_input()
            })
            .is_ok()
        );
    }

    #[test]
    fn input_validation_rejects_docs_p0_cases() {
        let mut input = base_input();
        input.purpose = "bad\nsecret-token".to_owned();
        assert!(normalize_input(input.clone()).is_err());
        input.purpose = "Check pod phases".to_owned();
        input.request_path = "/api/../secret".to_owned();
        assert!(normalize_input(input.clone()).is_err());
        input.request_path = "/api/v1/pods".to_owned();
        input.jsonpath = vec!["$..metadata.name".to_owned()];
        assert!(normalize_input(input.clone()).is_err());
        input.jsonpath = Vec::new();
        input
            .headers
            .insert("Accept".to_owned(), "text/plain".to_owned());
        assert!(normalize_input(input).is_err());
    }

    #[test]
    fn input_validation_rejects_query_boundary_violations() {
        let too_many = (0..=MAX_QUERY_KEYS)
            .map(|index| (format!("k{index}"), "v".to_owned()))
            .collect::<BTreeMap<_, _>>();
        assert!(
            normalize_input(ApiCallInput {
                query: too_many,
                ..base_input()
            })
            .is_err()
        );

        assert!(
            normalize_input(ApiCallInput {
                query: BTreeMap::from([("".to_owned(), "value".to_owned())]),
                ..base_input()
            })
            .is_err()
        );
        assert!(
            normalize_input(ApiCallInput {
                query: BTreeMap::from([("token".to_owned(), "secret\nleak".to_owned())]),
                ..base_input()
            })
            .is_err()
        );
        assert!(
            normalize_input(ApiCallInput {
                query: BTreeMap::from([("k".repeat(MAX_QUERY_KEY_LEN + 1), "v".to_owned())]),
                ..base_input()
            })
            .is_err()
        );
        assert!(
            normalize_input(ApiCallInput {
                query: BTreeMap::from([("k".to_owned(), "v".repeat(MAX_QUERY_VALUE_LEN + 1))]),
                ..base_input()
            })
            .is_err()
        );
    }

    #[test]
    fn input_validation_rejects_non_json_content_type_with_body() {
        let input = ApiCallInput {
            method: "POST".to_owned(),
            body: Some(serde_json::json!({"kind": "Pod"})),
            content_type: "text/plain".to_owned(),
            ..base_input()
        };
        assert!(normalize_input(input).is_err());
    }

    fn table_input(columns: &[(&str, &str)]) -> TableInput {
        TableInput {
            base: "$.items[*]".to_owned(),
            columns: columns
                .iter()
                .map(|(name, path)| ((*name).to_owned(), (*path).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn input_accepts_valid_table() -> Result<()> {
        let normalized = normalize_input(ApiCallInput {
            table: Some(table_input(&[("name", "$.metadata.name")])),
            ..base_input()
        })?;
        assert!(normalized.table.is_some());
        Ok(())
    }

    #[test]
    fn input_rejects_table_together_with_jsonpath() {
        let input = ApiCallInput {
            jsonpath: vec!["$.items[*].metadata.name".to_owned()],
            table: Some(table_input(&[("name", "$.metadata.name")])),
            ..base_input()
        };
        assert!(normalize_input(input).is_err());
    }

    #[test]
    fn input_rejects_table_with_no_columns() {
        let input = ApiCallInput {
            table: Some(table_input(&[])),
            ..base_input()
        };
        assert!(normalize_input(input).is_err());
    }

    #[test]
    fn input_rejects_table_paths_with_aggregates() {
        // A base aggregate must be rejected at input validation, before any
        // policy/credential/target execution — never as a post-request error.
        assert!(
            normalize_input(ApiCallInput {
                table: Some(TableInput {
                    base: "$.items.length()".to_owned(),
                    columns: BTreeMap::from([("name".to_owned(), "$.metadata.name".to_owned())]),
                }),
                ..base_input()
            })
            .is_err()
        );
        // Field aggregates are rejected too (table is flat columns only).
        assert!(
            normalize_input(ApiCallInput {
                table: Some(table_input(&[("n", "$.spec.containers.count()")])),
                ..base_input()
            })
            .is_err()
        );
    }

    #[test]
    fn input_rejects_invalid_table_column_names() {
        // empty after trim
        assert!(
            normalize_input(ApiCallInput {
                table: Some(table_input(&[("  ", "$.metadata.name")])),
                ..base_input()
            })
            .is_err()
        );
        // CR/LF
        assert!(
            normalize_input(ApiCallInput {
                table: Some(table_input(&[("na\nme", "$.metadata.name")])),
                ..base_input()
            })
            .is_err()
        );
        // NUL
        assert!(
            normalize_input(ApiCallInput {
                table: Some(table_input(&[("na\0me", "$.metadata.name")])),
                ..base_input()
            })
            .is_err()
        );
        // over the length limit
        let long = "n".repeat(MAX_TABLE_COLUMN_NAME_LEN + 1);
        assert!(
            normalize_input(ApiCallInput {
                table: Some(TableInput {
                    base: "$.items[*]".to_owned(),
                    columns: BTreeMap::from([(long, "$.metadata.name".to_owned())]),
                }),
                ..base_input()
            })
            .is_err()
        );
        // two names that collide only after trimming
        assert!(
            normalize_input(ApiCallInput {
                table: Some(table_input(&[("name", "$.a"), ("name ", "$.b")])),
                ..base_input()
            })
            .is_err()
        );
    }
}

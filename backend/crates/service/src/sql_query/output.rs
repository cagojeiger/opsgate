use crate::llm_output::{
    BodyMode, BodyState, JsonOutput, JsonOutputOptions, More, MoreOptions, NextAction, OmitReason,
    SourceBodyMode, build_json_output_from_value,
};
use opsgate_core::{Error, Result};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;

use super::input::{MAX_MAX_BYTES, NormalizedInput};
use super::policy::query_uses_select_wildcard;

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SqlQueryOutput {
    pub body_mode: BodyMode,
    pub body_state: BodyState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omit_reason: Option<OmitReason>,
    #[schemars(schema_with = "opsgate_core::schema::json_value_schema")]
    pub body: Value,
    /// Rows fetched from Postgres after max_rows enforcement, before JSONPath or byte truncation.
    pub row_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_limit: Option<RowLimit>,
    pub truncated: bool,
    pub original_bytes: usize,
    pub returned_bytes: usize,
    pub latency_ms: i64,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub more: Option<More>,
    #[serde(skip)]
    pub column_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
pub struct RowLimit {
    pub hit: bool,
    pub max_rows: i32,
}

pub(super) fn build_column_output(
    rows: Vec<Value>,
    input: &NormalizedInput,
    truncated: bool,
) -> Result<SqlQueryOutput> {
    let row_count = rows.len();
    let (body, column_names) = transpose_rows(rows)?;
    let shaped = build_shaped_body(body, input)?;
    let truncated_total = truncated || shaped.truncated;
    let more = finalize_more(shaped.more, truncated, input);

    Ok(SqlQueryOutput {
        body_mode: shaped.body_mode,
        body_state: shaped.body_state,
        omit_reason: shaped.omit_reason,
        body: shaped.body,
        row_count,
        row_limit: truncated.then_some(RowLimit {
            hit: true,
            max_rows: input.max_rows,
        }),
        truncated: truncated_total,
        original_bytes: shaped.original_bytes,
        returned_bytes: shaped.returned_bytes,
        latency_ms: 0,
        hints: output_hints(input),
        more,
        column_names,
    })
}

const SELECT_WILDCARD_HINT: &str =
    "Prefer explicit columns instead of SELECT * to reduce SQL output size.";

fn output_hints(input: &NormalizedInput) -> Vec<String> {
    if query_uses_select_wildcard(&input.query) {
        vec![SELECT_WILDCARD_HINT.to_owned()]
    } else {
        Vec::new()
    }
}

/// SQL-specific narrowing hint appended to byte-overflow guidance: unlike
/// api_call (where jsonpath is the only lever), sql_query can also rewrite the
/// query itself to shrink the result.
const SQL_NARROW_HINT: &str = "sql: you can also narrow the query (fewer columns / WHERE / aggregate) instead of only jsonpath";

/// Decide the final `more` guidance for a column output.
///
/// Byte-overflow guidance (`body=null`) takes precedence over row truncation
/// because the model received no rows at all; when it fires we only append a
/// SQL-specific narrowing hint to the shared jsonpath guidance. When the body
/// fit but rows were dropped by `max_rows`, synthesize a row-truncation `more`
/// so the model knows the next lever instead of seeing a bare `truncated:true`.
fn finalize_more(
    shaped_more: Option<More>,
    row_truncated: bool,
    input: &NormalizedInput,
) -> Option<More> {
    match shaped_more {
        Some(mut more) => {
            more.hints.push(SQL_NARROW_HINT.to_owned());
            Some(more)
        }
        None if row_truncated => Some(row_truncation_more(input)),
        None => None,
    }
}

fn row_truncation_more(input: &NormalizedInput) -> More {
    More {
        truncated: true,
        options: MoreOptions {
            next_action: NextAction::AdjustMaxRows,
            suggested_jsonpath: Vec::new(),
            suggested_max_bytes: None,
        },
        hints: vec![format!(
            "row limit reached (max_rows={}); raise max_rows up to policy, or narrow with WHERE / aggregate (count, group by) / keyset pagination",
            input.max_rows
        )],
        preview: None,
    }
}

fn build_shaped_body(body: Value, input: &NormalizedInput) -> Result<JsonOutput> {
    build_json_output_from_value(
        body,
        JsonOutputOptions {
            max_bytes: input.max_bytes,
            max_allowed_bytes: MAX_MAX_BYTES,
            json_paths: input.jsonpath.clone(),
            table: None,
            source_body_truncated: false,
            original_bytes: None,
            source_body_mode: SourceBodyMode::ColumnarJson,
        },
    )
}

fn transpose_rows(rows: Vec<Value>) -> Result<(Value, Vec<String>)> {
    let mut column_names = Vec::<String>::new();
    let mut column_values = Vec::<Vec<Value>>::new();

    for (row_index, row) in rows.into_iter().enumerate() {
        let mut object = match row {
            Value::Object(object) => object,
            _ => return Err(Error::internal("sql result row is not an object")),
        };
        for key in object.keys() {
            if !column_names.iter().any(|name| name == key) {
                column_names.push(key.clone());
                column_values.push(vec![Value::Null; row_index]);
            }
        }
        for (name, values) in column_names.iter().zip(column_values.iter_mut()) {
            values.push(object.remove(name).unwrap_or(Value::Null));
        }
    }

    let mut object = serde_json::Map::new();
    for (name, values) in column_names.iter().cloned().zip(column_values) {
        object.insert(name, Value::Array(values));
    }
    Ok((Value::Object(object), column_names))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> NormalizedInput {
        NormalizedInput {
            alias: "analytics".to_owned(),
            purpose: "Count recent rows".to_owned(),
            database: None,
            query: "select status, count(*) from payments group by status".to_owned(),
            params: Vec::new(),
            jsonpath: Vec::new(),
            max_rows: 100,
            max_bytes: 64 * 1024,
            timeout_ms: 3000,
            query_sha256: String::new(),
        }
    }

    #[test]
    fn flat_rows_become_column_oriented_body() -> Result<()> {
        let rows = vec![
            serde_json::json!({"status":"failed", "total": 42}),
            serde_json::json!({"status":"paid", "region": "us"}),
        ];
        let output = build_column_output(rows, &input(), false)?;

        assert_eq!(output.row_count, 2);
        assert_eq!(output.body_mode, BodyMode::ColumnarJson);
        assert_eq!(output.body_state, BodyState::Returned);
        assert_eq!(output.omit_reason, None);
        assert_eq!(output.row_limit, None);
        assert_eq!(
            output.column_names,
            vec!["status".to_owned(), "total".to_owned(), "region".to_owned()]
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
    fn row_truncation_emits_more_hint() -> Result<()> {
        let rows = vec![serde_json::json!({"id": 1}), serde_json::json!({"id": 2})];
        let mut input = input();
        input.max_rows = 2;
        let output = build_column_output(rows, &input, true)?;

        assert!(output.truncated);
        assert_eq!(
            output.row_limit,
            Some(RowLimit {
                hit: true,
                max_rows: 2,
            })
        );
        let more = output.more.ok_or_else(|| Error::internal("missing more"))?;
        assert_eq!(more.options.next_action, NextAction::AdjustMaxRows);
        assert!(more.options.suggested_jsonpath.is_empty());
        assert!(
            more.hints
                .iter()
                .any(|hint| hint.contains("max_rows=2") && hint.contains("WHERE"))
        );
        Ok(())
    }

    #[test]
    fn untruncated_output_has_no_more() -> Result<()> {
        let rows = vec![serde_json::json!({"id": 1})];
        let output = build_column_output(rows, &input(), false)?;

        assert!(!output.truncated);
        assert!(output.more.is_none());
        assert!(output.hints.is_empty());
        Ok(())
    }

    #[test]
    fn select_wildcard_output_emits_column_hint() -> Result<()> {
        let rows = vec![serde_json::json!({"id": 1, "status": "paid"})];
        let mut input = input();
        input.query = "select * from payments".to_owned();
        let output = build_column_output(rows, &input, false)?;

        assert!(
            output
                .hints
                .iter()
                .any(|hint| hint.contains("explicit columns") && hint.contains("SELECT *"))
        );
        assert!(output.more.is_none());
        Ok(())
    }

    #[test]
    fn byte_overflow_more_mentions_query_narrowing() -> Result<()> {
        let byte_more = More {
            truncated: true,
            options: MoreOptions {
                next_action: NextAction::AddJsonpath,
                suggested_jsonpath: Vec::new(),
                suggested_max_bytes: None,
            },
            hints: vec![
                "Opsgate read the full JSON, but the tool output budget is too small".to_owned(),
            ],
            preview: None,
        };
        let more = finalize_more(Some(byte_more), true, &input())
            .ok_or_else(|| Error::internal("more present"))?;

        assert_eq!(more.options.next_action, NextAction::AddJsonpath);
        assert!(
            more.hints
                .iter()
                .any(|hint| hint.contains("narrow the query"))
        );
        Ok(())
    }

    #[test]
    fn jsonpath_projects_one_column() -> Result<()> {
        let rows = vec![
            serde_json::json!({"status":"failed", "total": 42}),
            serde_json::json!({"status":"paid", "total": 900}),
        ];
        let mut input = input();
        input.jsonpath = vec!["$.status".to_owned()];
        let output = build_column_output(rows, &input, false)?;

        let projected = output
            .body
            .get("$.status")
            .ok_or_else(|| Error::internal("missing projected column"))?;
        assert_eq!(output.body_mode, BodyMode::JsonpathProjection);
        assert_eq!(output.body_state, BodyState::Returned);
        assert_eq!(output.omit_reason, None);
        assert_eq!(projected, &serde_json::json!([["failed", "paid"]]));
        assert_eq!(output.row_count, 2);
        assert_eq!(
            output.column_names,
            vec!["status".to_owned(), "total".to_owned()]
        );
        Ok(())
    }

    #[test]
    fn jsonpath_regex_filters_column_arrays() -> Result<()> {
        let rows = vec![
            serde_json::json!({"service":"api-main", "status":"paid"}),
            serde_json::json!({"service":"worker", "status":"failed"}),
            serde_json::json!({"service":"api-jobs", "status":"pending"}),
        ];
        let mut input = input();
        input.jsonpath = vec!["$.service[?search(@, '^api')]".to_owned()];
        let output = build_column_output(rows, &input, false)?;

        assert_eq!(
            output.body.get("$.service[?search(@, '^api')]"),
            Some(&serde_json::json!(["api-main", "api-jobs"]))
        );
        assert_eq!(output.row_count, 3);
        Ok(())
    }
}

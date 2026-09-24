use opsgate_core::{Error, Result};
use serde_json::{Map, Value};
use serde_json_path::JsonPath;

use super::types::TableProjection;

const MAX_JSON_PATHS: usize = 16;
const MAX_JSON_PATH_LEN: usize = 512;

pub fn validate_json_paths(paths: &[String]) -> Result<()> {
    if paths.len() > MAX_JSON_PATHS {
        return Err(Error::validation(format!(
            "too many jsonpath expressions ({} > {MAX_JSON_PATHS})",
            paths.len()
        )));
    }
    for path in paths {
        let trimmed = path.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_JSON_PATH_LEN {
            return Err(Error::validation("invalid jsonpath expression"));
        }
        if !trimmed.starts_with('$') {
            return Err(Error::validation(format!(
                "jsonpath expression {trimmed:?} must start with $"
            )));
        }
        if trimmed.contains("..") {
            return Err(Error::validation(
                "jsonpath recursive descent is outside the safe subset",
            ));
        }
        let (base_path, _operator) = split_jsonpath_operator(trimmed);
        parse_json_path(base_path, trimmed)?;
    }
    Ok(())
}

pub(super) fn project_json_paths(value: &Value, paths: &[String]) -> Result<Value> {
    let mut out = Map::new();
    for raw_path in paths {
        let path_key = raw_path.trim();
        let (base_path, operator) = split_jsonpath_operator(path_key);
        let path = parse_json_path(base_path, path_key)?;
        let nodes = path.query(value).all();
        let projected = match operator {
            Some(JsonPathOperator::Count) => count_projection(nodes.len()),
            Some(JsonPathOperator::Length) => length_projection(&nodes),
            None => Value::Array(nodes.into_iter().cloned().collect()),
        };
        out.insert(path_key.to_owned(), projected);
    }
    if out.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(Value::Object(out))
    }
}

/// Validate a table projection against the same RFC 9535 safe subset as keyed
/// projections. `base` and every field path are checked together.
pub fn validate_table_projection(table: &TableProjection) -> Result<()> {
    if table.columns.is_empty() {
        return Err(Error::validation("table requires at least one column"));
    }
    let mut paths = Vec::with_capacity(table.columns.len() + 1);
    paths.push(table.base.clone());
    paths.extend(table.columns.values().cloned());
    validate_json_paths(&paths)?;
    // Table is flat columns only: base and every column must be a plain
    // path with no count()/length() aggregate. Rejecting here (called from
    // normalize_input, before policy/credential/target execution) ensures an
    // invalid table never triggers a target call, and keeps the
    // missing-column = null contract unambiguous.
    for path in &paths {
        if split_jsonpath_operator(path.trim()).1.is_some() {
            return Err(Error::validation(
                "table paths must not use count() or length()",
            ));
        }
    }
    Ok(())
}

/// Reshape ragged JSON into an array of row objects: `base` enumerates the rows
/// and each column path is evaluated relative to a single row (its `$` rebinds to
/// the row node). Missing columns become `null`; a column matching multiple nodes
/// keeps them as an array. Mirrors the ISO SQL/JSON `JSON_TABLE` model.
pub(super) fn project_table(value: &Value, table: &TableProjection) -> Result<Value> {
    // Aggregates are rejected pre-execution by validate_table_projection, so base
    // and every field are plain RFC 9535 paths here.
    let base = parse_json_path(table.base.trim(), table.base.trim())?;
    // Parse every field path once, before iterating rows, so a projection over
    // N rows with M columns parses M paths rather than N*M.
    let mut columns = Vec::with_capacity(table.columns.len());
    for (column, raw_path) in &table.columns {
        let path_key = raw_path.trim();
        columns.push((column, parse_json_path(path_key, path_key)?));
    }
    let rows = base.query(value).all();
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut object = Map::new();
        for (column, path) in &columns {
            object.insert(
                (*column).clone(),
                collapse_field_nodes(path.query(row).all()),
            );
        }
        out.push(Value::Object(object));
    }
    Ok(Value::Array(out))
}

/// Collapse a field's matched nodes into one column value: none -> null,
/// one -> the value, many -> an array (no flattening).
fn collapse_field_nodes(nodes: Vec<&Value>) -> Value {
    match nodes.as_slice() {
        [] => Value::Null,
        [single] => (*single).clone(),
        _ => Value::Array(nodes.into_iter().cloned().collect()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonPathOperator {
    Count,
    Length,
}

fn split_jsonpath_operator(path: &str) -> (&str, Option<JsonPathOperator>) {
    for (suffix, operator) in [
        (".count()", JsonPathOperator::Count),
        (".count", JsonPathOperator::Count),
        (".length()", JsonPathOperator::Length),
        (".length", JsonPathOperator::Length),
    ] {
        if let Some(base) = path.strip_suffix(suffix)
            && !base.is_empty()
        {
            return (base, Some(operator));
        }
    }
    (path, None)
}

fn parse_json_path(base_path: &str, display_path: &str) -> Result<JsonPath> {
    JsonPath::parse(base_path).map_err(|error| {
        Error::validation(format!(
            "invalid jsonpath expression {display_path:?}: parser reported {:?} at position {}. Use RFC 9535 JSONPath; regex filters use search(value, pattern) for partial search or match(value, pattern) for full-string match.",
            error.message(),
            error.position()
        ))
    })
}

fn count_projection(count: usize) -> Value {
    serde_json::json!(count)
}

fn length_projection(nodes: &[&Value]) -> Value {
    let lengths = nodes
        .iter()
        .map(|node| value_length(node))
        .collect::<Vec<_>>();
    match lengths.as_slice() {
        [] => Value::Array(Vec::new()),
        [Some(length)] => serde_json::json!(length),
        [_one] => Value::Null,
        _ => Value::Array(
            lengths
                .into_iter()
                .map(|length| length.map_or(Value::Null, |length| serde_json::json!(length)))
                .collect(),
        ),
    }
}

fn value_length(value: &Value) -> Option<usize> {
    match value {
        Value::Array(items) => Some(items.len()),
        Value::Object(object) => Some(object.len()),
        Value::String(value) => Some(value.chars().count()),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }
}

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_json_path::JsonPath;

use crate::{Error, Result};

const DEFAULT_MAX_BYTES: usize = 4096;
const DEFAULT_MAX_ALLOWED_BYTES: usize = 1024 * 1024;
const MAX_JSON_PATHS: usize = 16;
const MAX_JSON_PATH_LEN: usize = 512;
const MAX_PREVIEW_BYTES: usize = 4096;
const MAX_PREVIEW_PATHS: usize = 20;
const MAX_PREVIEW_DEPTH: usize = 5;
const MAX_PREVIEW_ARRAY_SAMPLE: usize = 10;
const MAX_PREVIEW_NESTED_ARRAY_DEPTH: usize = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonOutputOptions {
    pub max_bytes: usize,
    pub max_allowed_bytes: usize,
    pub json_paths: Vec<String>,
    pub transport_truncated: bool,
    pub original_bytes: Option<usize>,
}

impl Default for JsonOutputOptions {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_allowed_bytes: DEFAULT_MAX_ALLOWED_BYTES,
            json_paths: Vec::new(),
            transport_truncated: false,
            original_bytes: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonOutput {
    pub body: Value,
    pub original_bytes: usize,
    pub returned_bytes: usize,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub more: Option<More>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct More {
    pub truncated: bool,
    pub options: MoreOptions,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<Preview>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MoreOptions {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub preferred_next: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub suggested_jsonpath: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Preview {
    pub path_count: usize,
    pub returned_paths: usize,
    pub truncated: bool,
    pub paths: Vec<PreviewPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreviewPath {
    pub path: String,
    #[serde(rename = "type")]
    pub value_type: String,
    pub present_sampled: usize,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub nulls_sampled: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub array_length_min_sampled: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub array_length_max_sampled: Option<usize>,
    #[serde(skip_serializing_if = "is_false", default)]
    pub nested_expansion_stopped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreviewStat {
    path: String,
    value_type: String,
    present: usize,
    nulls: usize,
    array_min: Option<usize>,
    array_max: Option<usize>,
    nested_expansion_stopped: bool,
}

pub fn build_json_output(raw: &[u8], options: JsonOutputOptions) -> Result<JsonOutput> {
    validate_json_paths(&options.json_paths)?;
    let original_bytes = options.original_bytes.unwrap_or(raw.len());
    if options.transport_truncated {
        return Ok(truncated_output(
            Value::Null,
            original_bytes,
            &options,
            None,
            true,
        ));
    }

    let parsed = decode_single_json_value(raw)?;
    let body = if options.json_paths.is_empty() {
        parsed
    } else {
        project_json_paths(&parsed, &options.json_paths)?
    };
    let marshaled = compact_json_bytes(&body)?;
    if marshaled.len() <= options.max_bytes {
        return Ok(JsonOutput {
            body,
            original_bytes,
            returned_bytes: marshaled.len(),
            truncated: false,
            more: None,
        });
    }

    let preview = if options.json_paths.is_empty() {
        build_preview(&body)
    } else {
        None
    };
    Ok(truncated_output(
        body,
        original_bytes,
        &options,
        preview,
        false,
    ))
}

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
        JsonPath::parse(trimmed).map_err(|error| {
            Error::validation(format!("invalid jsonpath expression {trimmed:?}: {error}"))
        })?;
    }
    Ok(())
}

fn decode_single_json_value(raw: &[u8]) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = Value::deserialize(&mut deserializer)
        .map_err(|error| Error::validation(format!("invalid JSON response: {error}")))?;
    deserializer
        .end()
        .map_err(|error| Error::validation(format!("invalid JSON response: {error}")))?;
    Ok(value)
}

fn project_json_paths(value: &Value, paths: &[String]) -> Result<Value> {
    let mut out = Map::new();
    for raw_path in paths {
        let path_key = raw_path.trim();
        let path = JsonPath::parse(path_key).map_err(|error| {
            Error::validation(format!("invalid jsonpath expression {path_key:?}: {error}"))
        })?;
        let nodes = path.query(value).all();
        if !nodes.is_empty() {
            out.insert(
                path_key.to_owned(),
                Value::Array(nodes.into_iter().cloned().collect()),
            );
        }
    }
    if out.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(Value::Object(out))
    }
}

fn truncated_output(
    body: Value,
    original_bytes: usize,
    options: &JsonOutputOptions,
    preview: Option<Preview>,
    transport_truncated: bool,
) -> JsonOutput {
    let more_options = truncation_options(options, preview.as_ref(), body_size(&body));
    JsonOutput {
        body: Value::Null,
        original_bytes,
        returned_bytes: 0,
        truncated: true,
        more: Some(More {
            truncated: true,
            hints: truncation_hints(options, &more_options, transport_truncated),
            options: more_options,
            preview,
        }),
    }
}

fn truncation_options(
    options: &JsonOutputOptions,
    preview: Option<&Preview>,
    body_bytes: usize,
) -> MoreOptions {
    let mut out = MoreOptions {
        preferred_next: if options.json_paths.is_empty() {
            "jsonpath".to_owned()
        } else {
            "narrow_jsonpath".to_owned()
        },
        suggested_jsonpath: Vec::new(),
        suggested_max_bytes: None,
    };
    if let Some(preview) = preview {
        out.suggested_jsonpath = suggested_json_paths(preview, 3);
    }
    if options.max_bytes < options.max_allowed_bytes {
        out.suggested_max_bytes = Some(body_bytes.min(options.max_allowed_bytes));
    }
    out
}

fn truncation_hints(
    options: &JsonOutputOptions,
    more_options: &MoreOptions,
    transport_truncated: bool,
) -> Vec<String> {
    if transport_truncated {
        return vec![
            "target response exceeded hard read cap; retry with narrower request or jsonpath"
                .to_owned(),
        ];
    }
    if options.json_paths.is_empty() {
        vec!["response JSON is too large; retry with jsonpath using 1-3 paths from suggested_jsonpath or preview.paths".to_owned()]
    } else {
        vec![format!(
            "jsonpath projection is still too large; reduce expression count/range before raising max_bytes to {:?}",
            more_options.suggested_max_bytes
        )]
    }
}

fn suggested_json_paths(preview: &Preview, limit: usize) -> Vec<String> {
    preview
        .paths
        .iter()
        .filter(|path| path.value_type != "object" && path.value_type != "array")
        .take(limit)
        .map(|path| path.path.clone())
        .collect()
}

fn build_preview(root: &Value) -> Option<Preview> {
    let mut stats = Vec::<PreviewStat>::new();
    collect_preview(&mut stats, "$", root, 0, 0);
    if stats.is_empty() {
        return None;
    }
    let path_count = stats.len();
    let mut paths = stats
        .into_iter()
        .map(|stat| PreviewPath {
            path: stat.path,
            value_type: stat.value_type,
            present_sampled: stat.present,
            nulls_sampled: stat.nulls,
            array_length_min_sampled: stat.array_min,
            array_length_max_sampled: stat.array_max,
            nested_expansion_stopped: stat.nested_expansion_stopped,
        })
        .collect::<Vec<_>>();
    paths.sort_by(|left, right| {
        score_preview_path(right)
            .cmp(&score_preview_path(left))
            .then_with(|| left.path.cmp(&right.path))
    });

    let mut truncated = false;
    if paths.len() > MAX_PREVIEW_PATHS {
        paths.truncate(MAX_PREVIEW_PATHS);
        truncated = true;
    }
    while preview_json_len(&paths) > MAX_PREVIEW_BYTES && !paths.is_empty() {
        paths.pop();
        truncated = true;
    }
    Some(Preview {
        path_count,
        returned_paths: paths.len(),
        truncated,
        paths,
    })
}

fn collect_preview(
    stats: &mut Vec<PreviewStat>,
    path: &str,
    value: &Value,
    depth: usize,
    array_depth: usize,
) {
    add_preview(stats, path, value);
    if depth >= MAX_PREVIEW_DEPTH {
        mark_stopped(stats, path);
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                collect_preview(
                    stats,
                    &format!("{path}{}", jsonpath_name_segment(key)),
                    child,
                    depth + 1,
                    array_depth,
                );
            }
        }
        Value::Array(items) => {
            if array_depth >= MAX_PREVIEW_NESTED_ARRAY_DEPTH {
                mark_stopped(stats, path);
                return;
            }
            for child in items.iter().take(MAX_PREVIEW_ARRAY_SAMPLE) {
                collect_preview(
                    stats,
                    &format!("{path}[*]"),
                    child,
                    depth + 1,
                    array_depth + 1,
                );
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn add_preview(stats: &mut Vec<PreviewStat>, path: &str, value: &Value) {
    let value_type = value_type(value);
    if let Some(stat) = stats.iter_mut().find(|stat| stat.path == path) {
        stat.present += 1;
        if value.is_null() {
            stat.nulls += 1;
        }
        if let Value::Array(items) = value {
            stat.array_min = Some(
                stat.array_min
                    .map_or(items.len(), |min| min.min(items.len())),
            );
            stat.array_max = Some(
                stat.array_max
                    .map_or(items.len(), |max| max.max(items.len())),
            );
        }
        return;
    }

    let (array_min, array_max) = match value {
        Value::Array(items) => (Some(items.len()), Some(items.len())),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Object(_) => {
            (None, None)
        }
    };
    stats.push(PreviewStat {
        path: path.to_owned(),
        value_type: value_type.to_owned(),
        present: 1,
        nulls: usize::from(value.is_null()),
        array_min,
        array_max,
        nested_expansion_stopped: false,
    });
}

fn mark_stopped(stats: &mut [PreviewStat], path: &str) {
    if let Some(stat) = stats.iter_mut().find(|stat| stat.path == path) {
        stat.nested_expansion_stopped = true;
    }
}

fn score_preview_path(path: &PreviewPath) -> isize {
    let mut score = isize::try_from(path.present_sampled).unwrap_or(isize::MAX);
    if path.nested_expansion_stopped {
        score -= 1000;
    }
    match path.value_type.as_str() {
        "object" => score -= 200,
        "array" => score -= 100,
        _ => {}
    }
    score
}

fn jsonpath_name_segment(name: &str) -> String {
    let escaped = name.replace('\\', "\\\\").replace('\'', "\\'");
    format!("['{escaped}']")
}

fn value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn body_size(body: &Value) -> usize {
    compact_json_bytes(body).map_or(0, |bytes| bytes.len())
}

fn preview_json_len(paths: &[PreviewPath]) -> usize {
    serde_json::to_vec(paths).map_or(MAX_PREVIEW_BYTES + 1, |bytes| bytes.len())
}

fn compact_json_bytes(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|error| Error::internal(format!("serialize JSON output: {error}")))
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|path| (*path).to_owned()).collect()
    }

    #[test]
    fn returns_inline_json_when_under_budget() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"name":"api"},{"name":"worker"}]}"#,
            JsonOutputOptions {
                max_bytes: 4096,
                ..JsonOutputOptions::default()
            },
        )?;
        assert!(!out.truncated);
        assert!(out.returned_bytes > 0);
        assert!(out.more.is_none());
        Ok(())
    }

    #[test]
    fn applies_jsonpath_projection_as_flat_keyed_object() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"metadata":{"name":"api"},"status":{"phase":"Running"}},{"metadata":{"name":"worker"},"status":{"phase":"Pending"}}]}"#,
            JsonOutputOptions {
                max_bytes: 4096,
                json_paths: paths(&["$.items[?@.status.phase == 'Running'].metadata.name"]),
                ..JsonOutputOptions::default()
            },
        )?;
        let value = out
            .body
            .get("$.items[?@.status.phase == 'Running'].metadata.name");
        assert_eq!(value, Some(&serde_json::json!(["api"])));
        Ok(())
    }

    #[test]
    fn truncates_large_json_with_preview_and_jsonpath_hint() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"metadata":{"name":"api"},"status":{"phase":"Running"}},{"metadata":{"name":"worker"},"status":{"phase":"Pending"}}]}"#,
            JsonOutputOptions {
                max_bytes: 32,
                ..JsonOutputOptions::default()
            },
        )?;
        assert!(out.truncated);
        assert_eq!(out.body, Value::Null);
        let more = out.more.ok_or_else(|| Error::internal("missing more"))?;
        assert_eq!(more.options.preferred_next, "jsonpath");
        assert!(
            more.options
                .suggested_jsonpath
                .iter()
                .any(|path| path == "$['items'][*]['metadata']['name']")
        );
        assert!(more.preview.is_some());
        Ok(())
    }

    #[test]
    fn truncates_oversized_projection_with_narrow_hint() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"name":"api"},{"name":"worker"}]}"#,
            JsonOutputOptions {
                max_bytes: 16,
                json_paths: paths(&["$.items[*].name"]),
                ..JsonOutputOptions::default()
            },
        )?;
        let more = out.more.ok_or_else(|| Error::internal("missing more"))?;
        assert_eq!(more.options.preferred_next, "narrow_jsonpath");
        assert!(more.preview.is_none());
        Ok(())
    }

    #[test]
    fn validates_jsonpath_limits_before_processing() {
        let too_many = vec!["$".to_owned(); 17];
        assert!(validate_json_paths(&too_many).is_err());
        assert!(validate_json_paths(&["items".to_owned()]).is_err());
        assert!(validate_json_paths(&[format!("${}", "a".repeat(513))]).is_err());
    }

    #[test]
    fn rejects_multiple_top_level_json_values() {
        let err = build_json_output(br#"{} {}"#, JsonOutputOptions::default()).err();
        assert!(err.is_some());
    }

    #[test]
    fn transport_truncation_preserves_reported_original_size() -> Result<()> {
        let out = build_json_output(
            br#"{"partial":true}"#,
            JsonOutputOptions {
                transport_truncated: true,
                original_bytes: Some(2048),
                ..JsonOutputOptions::default()
            },
        )?;
        assert!(out.truncated);
        assert_eq!(out.original_bytes, 2048);
        assert_eq!(out.returned_bytes, 0);
        Ok(())
    }
}

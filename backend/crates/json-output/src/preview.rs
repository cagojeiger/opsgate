use std::collections::HashMap;

use serde_json::Value;

use super::types::{Preview, PreviewPath};

const MAX_PREVIEW_BYTES: usize = 4096;
pub(super) const MAX_PREVIEW_PATHS: usize = 20;
const MAX_PREVIEW_DEPTH: usize = 5;
const MAX_PREVIEW_ARRAY_SAMPLE: usize = 10;
const MAX_PREVIEW_NESTED_ARRAY_DEPTH: usize = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreviewStat {
    value_type: String,
    present: usize,
    nulls: usize,
    array_min: Option<usize>,
    array_max: Option<usize>,
    nested_expansion_stopped: bool,
}

pub(super) fn build_preview(root: &Value) -> Option<Preview> {
    let mut stats = HashMap::<String, PreviewStat>::new();
    collect_preview(&mut stats, "$", root, 0, 0);
    if stats.is_empty() {
        return None;
    }
    let path_count = stats.len();
    let mut paths = stats
        .into_iter()
        .map(|(path, stat)| PreviewPath {
            path,
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
    stats: &mut HashMap<String, PreviewStat>,
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

fn add_preview(stats: &mut HashMap<String, PreviewStat>, path: &str, value: &Value) {
    let value_type = value_type(value);
    if let Some(stat) = stats.get_mut(path) {
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
    stats.insert(
        path.to_owned(),
        PreviewStat {
            value_type: value_type.to_owned(),
            present: 1,
            nulls: usize::from(value.is_null()),
            array_min,
            array_max,
            nested_expansion_stopped: false,
        },
    );
}

fn mark_stopped(stats: &mut HashMap<String, PreviewStat>, path: &str) {
    if let Some(stat) = stats.get_mut(path) {
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
    if jsonpath_dot_name_allowed(name) {
        return format!(".{name}");
    }
    let escaped = name.replace('\\', "\\\\").replace('\'', "\\'");
    format!("['{escaped}']")
}

fn jsonpath_dot_name_allowed(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|char| char == '_' || char.is_ascii_alphanumeric())
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

fn preview_json_len(paths: &[PreviewPath]) -> usize {
    serde_json::to_vec(paths).map_or(MAX_PREVIEW_BYTES + 1, |bytes| bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_paths_keep_sample_counts_and_ranked_order() -> opsgate_core::Result<()> {
        let value = serde_json::json!({
            "items": [{"x": 1, "y": null}, {"x": 2, "y": 3}]
        });
        let preview = build_preview(&value)
            .ok_or_else(|| opsgate_core::Error::internal("missing preview"))?;
        let paths = preview
            .paths
            .iter()
            .map(|path| path.path.as_str())
            .collect::<Vec<_>>();

        assert_eq!(preview.path_count, 5);
        assert_eq!(
            paths,
            ["$.items[*].x", "$.items[*].y", "$.items", "$.items[*]", "$"]
        );
        assert_eq!(
            preview.paths.first().map(|path| path.present_sampled),
            Some(2)
        );
        assert_eq!(
            preview.paths.get(1).map(|path| path.present_sampled),
            Some(2)
        );
        assert_eq!(preview.paths.get(1).map(|path| path.nulls_sampled), Some(1));
        Ok(())
    }
}

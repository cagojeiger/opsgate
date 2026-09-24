use opsgate_core::{Error, Result};
use serde::Deserialize;
use serde_json::Value;

use super::preview::build_preview;
use super::projection::{
    project_json_paths, project_table, validate_json_paths, validate_table_projection,
};
use super::types::{
    BodyMode, BodyState, JsonOutput, JsonOutputOptions, More, MoreOptions, NextAction, OmitReason,
    Preview,
};

pub fn build_json_output(raw: &[u8], options: JsonOutputOptions) -> Result<JsonOutput> {
    validate_json_paths(&options.json_paths)?;
    if let Some(table) = &options.table {
        validate_table_projection(table)?;
    }
    let original_bytes = options.original_bytes.unwrap_or(raw.len());
    if options.source_body_truncated {
        return Ok(truncated_output(
            original_bytes,
            &options,
            None,
            0,
            OmitReason::Source,
        ));
    }

    let parsed = decode_single_json_value(raw)?;
    shape_output(parsed, original_bytes, &options)
}

/// Shape an already-parsed JSON value for return, skipping the byte parse step.
///
/// Callers that build the value in-process (e.g. `sql_query` columnar output)
/// would otherwise serialize to bytes only for [`build_json_output`] to parse
/// them straight back. This applies the same JSONPath projection, byte cap, and
/// truncation guidance directly on the owned value, matching `build_json_output`
/// byte-for-byte (`compact_json_bytes` is `serde_json::to_vec`).
pub fn build_json_output_from_value(
    value: Value,
    options: JsonOutputOptions,
) -> Result<JsonOutput> {
    validate_json_paths(&options.json_paths)?;
    if let Some(table) = &options.table {
        validate_table_projection(table)?;
    }
    if options.source_body_truncated {
        return Ok(truncated_output(
            options.original_bytes.unwrap_or(0),
            &options,
            None,
            0,
            OmitReason::Source,
        ));
    }

    if !options.is_projection() {
        // The whole value is the body, so one serialization covers both the
        // original and returned byte counts.
        let body_bytes = compact_json_bytes(&value)?.len();
        let original_bytes = options.original_bytes.unwrap_or(body_bytes);
        return Ok(finish_output(value, original_bytes, body_bytes, &options));
    }

    let original_bytes = match options.original_bytes {
        Some(bytes) => bytes,
        None => compact_json_bytes(&value)?.len(),
    };
    shape_output(value, original_bytes, &options)
}

fn shape_output(
    value: Value,
    original_bytes: usize,
    options: &JsonOutputOptions,
) -> Result<JsonOutput> {
    let body = match &options.table {
        Some(table) => project_table(&value, table)?,
        None if options.json_paths.is_empty() => value,
        None => project_json_paths(&value, &options.json_paths)?,
    };
    let body_bytes = compact_json_bytes(&body)?.len();
    Ok(finish_output(body, original_bytes, body_bytes, options))
}

fn finish_output(
    body: Value,
    original_bytes: usize,
    body_bytes: usize,
    options: &JsonOutputOptions,
) -> JsonOutput {
    if body_bytes <= options.max_bytes {
        return JsonOutput {
            body_mode: output_body_mode(options),
            body_state: BodyState::Returned,
            omit_reason: None,
            body,
            original_bytes,
            returned_bytes: body_bytes,
            truncated: false,
            more: None,
        };
    }
    let preview = if options.is_projection() {
        None
    } else {
        build_preview(&body)
    };
    truncated_output(
        original_bytes,
        options,
        preview,
        body_bytes,
        output_budget_omit_reason(options),
    )
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

fn truncated_output(
    original_bytes: usize,
    options: &JsonOutputOptions,
    preview: Option<Preview>,
    body_bytes: usize,
    omit_reason: OmitReason,
) -> JsonOutput {
    let more_options = truncation_options(options, preview.as_ref(), body_bytes, omit_reason);
    JsonOutput {
        body_mode: output_body_mode(options),
        body_state: BodyState::Omitted,
        omit_reason: Some(omit_reason),
        body: Value::Null,
        original_bytes,
        returned_bytes: 0,
        truncated: true,
        more: Some(More {
            truncated: true,
            hints: truncation_hints(options, omit_reason, &more_options),
            options: more_options,
            preview,
        }),
    }
}

fn output_body_mode(options: &JsonOutputOptions) -> BodyMode {
    if options.table.is_some() {
        BodyMode::TableProjection
    } else if options.json_paths.is_empty() {
        options.source_body_mode.into()
    } else {
        BodyMode::JsonpathProjection
    }
}

fn output_budget_omit_reason(options: &JsonOutputOptions) -> OmitReason {
    if options.is_projection() {
        OmitReason::Projection
    } else {
        OmitReason::Output
    }
}

fn next_action(options: &JsonOutputOptions, omit_reason: OmitReason) -> NextAction {
    match omit_reason {
        OmitReason::Source => NextAction::NarrowRequest,
        OmitReason::Output => NextAction::AddJsonpath,
        OmitReason::Projection if options.table.is_some() => NextAction::NarrowTableProjection,
        OmitReason::Projection => NextAction::NarrowJsonpath,
    }
}

fn truncation_options(
    options: &JsonOutputOptions,
    preview: Option<&Preview>,
    body_bytes: usize,
    omit_reason: OmitReason,
) -> MoreOptions {
    let mut out = MoreOptions {
        next_action: next_action(options, omit_reason),
        suggested_jsonpath: Vec::new(),
        suggested_max_bytes: None,
    };
    if let Some(preview) = preview {
        out.suggested_jsonpath = suggested_json_paths(preview, 3);
    }
    if omit_reason != OmitReason::Source && options.max_bytes < options.max_allowed_bytes {
        out.suggested_max_bytes = Some(body_bytes.min(options.max_allowed_bytes));
    }
    out
}

fn truncation_hints(
    options: &JsonOutputOptions,
    omit_reason: OmitReason,
    more_options: &MoreOptions,
) -> Vec<String> {
    match omit_reason {
        OmitReason::Source => vec![
            "Opsgate could not read the full target response body; retry with target-native pagination, filters, selectors, limits, time ranges, or a narrower path/query/body"
                .to_owned(),
        ],
        OmitReason::Output => vec![
            "Opsgate read the full JSON, but the tool output budget is too small; inspect preview.paths, then retry with jsonpath using 1-3 selected paths. suggested_jsonpath is only a small shortlist.".to_owned(),
        ],
        OmitReason::Projection if options.table.is_some() => vec![format!(
            "Opsgate read the full JSON, but the table is still too large; drop columns, narrow the base row set, or raise max_bytes to {:?}",
            more_options.suggested_max_bytes
        )],
        OmitReason::Projection => vec![format!(
            "Opsgate read the full JSON, but the JSONPath projection is still too large; reduce expression count, slice range, or filter scope before raising max_bytes to {:?}",
            more_options.suggested_max_bytes
        )],
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

fn compact_json_bytes(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|error| Error::internal(format!("serialize JSON output: {error}")))
}

#[cfg(test)]
mod tests {
    use serde_json::Map;

    use super::*;
    use crate::preview::MAX_PREVIEW_PATHS;
    use crate::types::{SourceBodyMode, TableProjection};

    fn paths(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|path| (*path).to_owned()).collect()
    }

    fn table_proj(base: &str, columns: &[(&str, &str)]) -> TableProjection {
        TableProjection {
            base: base.to_owned(),
            columns: columns
                .iter()
                .map(|(name, path)| ((*name).to_owned(), (*path).to_owned()))
                .collect(),
        }
    }

    fn validation_error(path: &str) -> Result<String> {
        match validate_json_paths(&[path.to_owned()]) {
            Ok(()) => Err(Error::internal(format!(
                "expected jsonpath validation error for {path:?}"
            ))),
            Err(error) => Ok(error.to_string()),
        }
    }

    #[test]
    fn from_value_matches_byte_path_across_cases() -> Result<()> {
        let value = serde_json::json!({
            "items": [
                {"metadata": {"name": "api"}, "status": {"phase": "Running"}},
                {"metadata": {"name": "worker"}, "status": {"phase": "Pending"}}
            ]
        });
        let raw = serde_json::to_vec(&value).map_err(|error| Error::internal(error.to_string()))?;
        let cases = [
            JsonOutputOptions {
                max_bytes: 4096,
                ..JsonOutputOptions::default()
            },
            JsonOutputOptions {
                max_bytes: 4096,
                json_paths: paths(&["$.items[*].metadata.name"]),
                ..JsonOutputOptions::default()
            },
            JsonOutputOptions {
                max_bytes: 16,
                ..JsonOutputOptions::default()
            },
            JsonOutputOptions {
                max_bytes: 16,
                json_paths: paths(&["$.items[*].metadata.name"]),
                ..JsonOutputOptions::default()
            },
            JsonOutputOptions {
                table: Some(table_proj("$.items[*]", &[("name", "$.metadata.name")])),
                ..JsonOutputOptions::default()
            },
            JsonOutputOptions {
                max_bytes: 16,
                table: Some(table_proj("$.items[*]", &[("name", "$.metadata.name")])),
                ..JsonOutputOptions::default()
            },
            JsonOutputOptions {
                original_bytes: Some(2048),
                source_body_mode: SourceBodyMode::ColumnarJson,
                ..JsonOutputOptions::default()
            },
            JsonOutputOptions {
                original_bytes: Some(2048),
                json_paths: paths(&["$.items[*].metadata.name"]),
                ..JsonOutputOptions::default()
            },
            JsonOutputOptions {
                source_body_truncated: true,
                original_bytes: Some(2048),
                ..JsonOutputOptions::default()
            },
            JsonOutputOptions {
                source_body_truncated: true,
                original_bytes: Some(2048),
                table: Some(table_proj("$.items[*]", &[("name", "$.metadata.name")])),
                ..JsonOutputOptions::default()
            },
        ];
        for options in cases {
            let from_bytes = build_json_output(&raw, options.clone())?;
            let from_value = build_json_output_from_value(value.clone(), options)?;
            assert_eq!(from_bytes, from_value);
        }
        Ok(())
    }

    #[test]
    fn byte_input_keeps_original_spacing_in_byte_count() -> Result<()> {
        let raw = "{ \"name\": \"한글\" }\n".as_bytes();
        let value = serde_json::json!({"name": "한글"});
        let compact_len = compact_json_bytes(&value)?.len();
        let from_bytes = build_json_output(raw, JsonOutputOptions::default())?;
        let from_value = build_json_output_from_value(value, JsonOutputOptions::default())?;
        assert_eq!(from_bytes.original_bytes, raw.len());
        assert_eq!(from_value.original_bytes, compact_len);
        assert_eq!(from_bytes.returned_bytes, compact_len);
        assert_eq!(from_bytes.body, from_value.body);
        Ok(())
    }

    #[test]
    fn source_truncation_keeps_entry_point_byte_defaults() -> Result<()> {
        let raw = br#"{"partial":"#;
        let options = JsonOutputOptions {
            source_body_truncated: true,
            ..JsonOutputOptions::default()
        };
        let from_bytes = build_json_output(raw, options.clone())?;
        let from_value = build_json_output_from_value(Value::Null, options)?;
        assert_eq!(from_bytes.original_bytes, raw.len());
        assert_eq!(from_value.original_bytes, 0);
        assert_eq!(from_bytes.omit_reason, Some(OmitReason::Source));
        assert_eq!(from_value.omit_reason, Some(OmitReason::Source));
        Ok(())
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
        assert_eq!(out.body_mode, BodyMode::RawJson);
        assert_eq!(out.body_state, BodyState::Returned);
        assert_eq!(out.omit_reason, None);
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
        assert_eq!(out.body_mode, BodyMode::JsonpathProjection);
        assert_eq!(out.body_state, BodyState::Returned);
        assert_eq!(out.omit_reason, None);
        assert_eq!(value, Some(&serde_json::json!(["api"])));
        Ok(())
    }

    #[test]
    fn table_reshapes_into_one_object_per_row() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"metadata":{"name":"vault-0"},"status":{"phase":"Running"}},{"metadata":{"name":"vault-1"},"status":{}}]}"#,
            JsonOutputOptions {
                max_bytes: 4096,
                table: Some(table_proj(
                    "$.items[*]",
                    &[("name", "$.metadata.name"), ("phase", "$.status.phase")],
                )),
                ..JsonOutputOptions::default()
            },
        )?;
        assert_eq!(out.body_mode, BodyMode::TableProjection);
        assert_eq!(out.body_state, BodyState::Returned);
        assert_eq!(out.omit_reason, None);
        // Row-aligned objects; the second row's missing phase becomes null.
        assert_eq!(
            out.body,
            serde_json::json!([
                {"name": "vault-0", "phase": "Running"},
                {"name": "vault-1", "phase": null}
            ])
        );
        Ok(())
    }

    #[test]
    fn table_keeps_multi_node_column_as_array() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"spec":{"containers":[{"name":"a"},{"name":"b"}]}}]}"#,
            JsonOutputOptions {
                max_bytes: 4096,
                table: Some(table_proj(
                    "$.items[*]",
                    &[("containers", "$.spec.containers[*].name")],
                )),
                ..JsonOutputOptions::default()
            },
        )?;
        assert_eq!(out.body, serde_json::json!([{"containers": ["a", "b"]}]));
        Ok(())
    }

    #[test]
    fn table_oversize_hints_narrow_table_not_jsonpath() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"metadata":{"name":"vault-0"},"status":{"phase":"Running"}},{"metadata":{"name":"vault-1"},"status":{"phase":"Pending"}}]}"#,
            JsonOutputOptions {
                max_bytes: 10,
                table: Some(table_proj(
                    "$.items[*]",
                    &[("name", "$.metadata.name"), ("phase", "$.status.phase")],
                )),
                ..JsonOutputOptions::default()
            },
        )?;
        assert_eq!(out.body_mode, BodyMode::TableProjection);
        assert_eq!(out.body_state, BodyState::Omitted);
        assert_eq!(out.omit_reason, Some(OmitReason::Projection));
        let more = out
            .more
            .ok_or_else(|| Error::internal("missing more envelope"))?;
        // Row mode must NOT tell the LLM to narrow a jsonpath it never used.
        assert_eq!(more.options.next_action, NextAction::NarrowTableProjection);
        assert!(more.hints.iter().any(|hint| hint.contains("table")));
        Ok(())
    }

    #[test]
    fn table_rejects_empty_columns_and_unsafe_paths() {
        let empty = TableProjection {
            base: "$.items[*]".to_owned(),
            columns: std::collections::BTreeMap::new(),
        };
        assert!(validate_table_projection(&empty).is_err());

        let recursive = table_proj("$.items[*]", &[("name", "$..name")]);
        assert!(validate_table_projection(&recursive).is_err());
    }

    #[test]
    fn from_value_reports_columnar_source_body_mode() -> Result<()> {
        let out = build_json_output_from_value(
            serde_json::json!({"status":["failed","paid"],"total":[42,900]}),
            JsonOutputOptions {
                max_bytes: 4096,
                source_body_mode: SourceBodyMode::ColumnarJson,
                ..JsonOutputOptions::default()
            },
        )?;

        assert_eq!(out.body_mode, BodyMode::ColumnarJson);
        assert_eq!(out.body_state, BodyState::Returned);
        assert_eq!(out.omit_reason, None);
        Ok(())
    }

    #[test]
    fn jsonpath_count_and_length_project_small_scalars() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"metadata":{"name":"api"},"status":{"phase":"Running"}},{"metadata":{"name":"worker"},"status":{"phase":"Pending"}}],"name":"abcd"}"#,
            JsonOutputOptions {
                max_bytes: 4096,
                json_paths: paths(&[
                    "$.items.length()",
                    "$.items[*].metadata.name.count()",
                    "$.name.length",
                ]),
                ..JsonOutputOptions::default()
            },
        )?;

        assert_eq!(
            out.body.get("$.items.length()"),
            Some(&serde_json::json!(2))
        );
        assert_eq!(
            out.body.get("$.items[*].metadata.name.count()"),
            Some(&serde_json::json!(2))
        );
        assert_eq!(out.body.get("$.name.length"), Some(&serde_json::json!(4)));
        assert_eq!(out.returned_bytes, compact_json_bytes(&out.body)?.len());
        Ok(())
    }

    #[test]
    fn jsonpath_regex_functions_filter_string_values() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"metadata":{"name":"api"}},{"metadata":{"name":"worker"}},{"metadata":{"name":"db"}}]}"#,
            JsonOutputOptions {
                max_bytes: 4096,
                json_paths: paths(&[
                    "$.items[?search(@.metadata.name, 'wo')].metadata.name",
                    "$.items[?match(@.metadata.name, 'a.*')].metadata.name",
                ]),
                ..JsonOutputOptions::default()
            },
        )?;

        assert_eq!(
            out.body
                .get("$.items[?search(@.metadata.name, 'wo')].metadata.name"),
            Some(&serde_json::json!(["worker"]))
        );
        assert_eq!(
            out.body
                .get("$.items[?match(@.metadata.name, 'a.*')].metadata.name"),
            Some(&serde_json::json!(["api"]))
        );
        Ok(())
    }

    #[test]
    fn jsonpath_regex_filters_compose_with_boolean_predicates() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"metadata":{"name":"api-1"},"status":{"phase":"Running"}},{"metadata":{"name":"api-2"},"status":{"phase":"Pending"}},{"metadata":{"name":"worker"},"status":{"phase":"Running"}}]}"#,
            JsonOutputOptions {
                max_bytes: 4096,
                json_paths: paths(&[
                    "$.items[?@.status.phase == 'Running' && search(@.metadata.name, '^api')].metadata.name",
                    "$.items[?@.status.phase == 'Running' && match(@.metadata.name, 'worker')].metadata.name",
                ]),
                ..JsonOutputOptions::default()
            },
        )?;

        assert_eq!(
            out.body.get(
                "$.items[?@.status.phase == 'Running' && search(@.metadata.name, '^api')].metadata.name"
            ),
            Some(&serde_json::json!(["api-1"]))
        );
        assert_eq!(
            out.body.get(
                "$.items[?@.status.phase == 'Running' && match(@.metadata.name, 'worker')].metadata.name"
            ),
            Some(&serde_json::json!(["worker"]))
        );
        Ok(())
    }

    #[test]
    fn jsonpath_regex_functions_return_empty_for_non_string_inputs() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"name":123},{"name":null},{"name":"api"}]}"#,
            JsonOutputOptions {
                max_bytes: 4096,
                json_paths: paths(&["$.items[?search(@.name, 'api')].name"]),
                ..JsonOutputOptions::default()
            },
        )?;

        assert_eq!(
            out.body.get("$.items[?search(@.name, 'api')].name"),
            Some(&serde_json::json!(["api"]))
        );
        Ok(())
    }

    #[test]
    fn jsonpath_length_projects_multiple_node_lengths() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"containers":[1,2]},{"containers":[3]}]}"#,
            JsonOutputOptions {
                max_bytes: 4096,
                json_paths: paths(&["$.items[*].containers.length()"]),
                ..JsonOutputOptions::default()
            },
        )?;

        assert_eq!(
            out.body.get("$.items[*].containers.length()"),
            Some(&serde_json::json!([2, 1]))
        );
        Ok(())
    }

    #[test]
    fn truncates_large_json_with_preview_catalog_and_shortlist() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"metadata":{"name":"api"},"status":{"phase":"Running"}},{"metadata":{"name":"worker"},"status":{"phase":"Pending"}}]}"#,
            JsonOutputOptions {
                max_bytes: 32,
                ..JsonOutputOptions::default()
            },
        )?;
        assert!(out.truncated);
        assert_eq!(out.body_mode, BodyMode::RawJson);
        assert_eq!(out.body_state, BodyState::Omitted);
        assert_eq!(out.omit_reason, Some(OmitReason::Output));
        assert_eq!(out.body, Value::Null);
        let more = out.more.ok_or_else(|| Error::internal("missing more"))?;
        assert_eq!(more.options.next_action, NextAction::AddJsonpath);
        assert!(
            more.options
                .suggested_jsonpath
                .iter()
                .any(|path| path == "$.items[*].metadata.name")
        );
        assert!(more.preview.is_some());
        assert!(more.options.suggested_max_bytes.is_some());
        assert!(more.hints.iter().any(|hint| {
            hint.contains("inspect preview.paths") && hint.contains("small shortlist")
        }));
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
        assert_eq!(out.body_mode, BodyMode::JsonpathProjection);
        assert_eq!(out.body_state, BodyState::Omitted);
        assert_eq!(out.omit_reason, Some(OmitReason::Projection));
        let more = out.more.ok_or_else(|| Error::internal("missing more"))?;
        assert_eq!(more.options.next_action, NextAction::NarrowJsonpath);
        assert!(more.preview.is_none());
        assert!(more.hints.iter().any(|hint| {
            hint.contains("read the full JSON") && hint.contains("projection is still too large")
        }));
        Ok(())
    }

    #[test]
    fn serializes_omit_reasons_and_next_actions_as_llm_terms() -> Result<()> {
        assert_eq!(
            serde_json::to_value(OmitReason::Output).map_err(Error::internal)?,
            serde_json::json!("output_body_too_large")
        );
        assert_eq!(
            serde_json::to_value(OmitReason::Projection).map_err(Error::internal)?,
            serde_json::json!("projection_body_too_large")
        );
        assert_eq!(
            serde_json::to_value(OmitReason::Source).map_err(Error::internal)?,
            serde_json::json!("source_body_too_large")
        );
        assert_eq!(
            serde_json::to_value(NextAction::AddJsonpath).map_err(Error::internal)?,
            serde_json::json!("add_jsonpath")
        );
        assert_eq!(
            serde_json::to_value(NextAction::AdjustMaxRows).map_err(Error::internal)?,
            serde_json::json!("adjust_max_rows")
        );
        Ok(())
    }

    #[test]
    fn validates_jsonpath_limits_before_processing() -> Result<()> {
        let too_many = vec!["$".to_owned(); 17];
        assert!(validate_json_paths(&too_many).is_err());
        assert!(validate_json_paths(&["items".to_owned()]).is_err());
        assert!(validate_json_paths(&[format!("${}", "a".repeat(513))]).is_err());
        assert!(validate_json_paths(&["$..metadata.name".to_owned()]).is_err());
        let err = validation_error("$.items[?(@.metadata.name =~ /api/)].metadata.name")?;
        assert!(err.contains("parser reported"));
        assert!(err.contains("at position"));
        assert!(err.contains("Use RFC 9535 JSONPath"));
        assert!(err.contains("search(value, pattern)"));
        assert!(err.contains("match(value, pattern)"));
        Ok(())
    }

    #[test]
    fn jsonpath_invalid_regex_pattern_returns_no_matches() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"name":"api"}]}"#,
            JsonOutputOptions {
                max_bytes: 4096,
                json_paths: paths(&["$.items[?search(@.name, '[')].name"]),
                ..JsonOutputOptions::default()
            },
        )?;

        assert_eq!(
            out.body.get("$.items[?search(@.name, '[')].name"),
            Some(&serde_json::json!([]))
        );
        Ok(())
    }

    #[test]
    fn jsonpath_parse_error_reports_parser_reason_and_common_regex_rule() -> Result<()> {
        let err = validation_error("$.items[?foo(@.metadata.name, 'api')].metadata.name")?;
        assert!(err.contains("parser reported"));
        assert!(err.contains("function name 'foo' is not defined"));
        assert!(err.contains("at position"));
        assert!(err.contains("Use RFC 9535 JSONPath"));
        assert!(err.contains("search(value, pattern)"));
        assert!(err.contains("match(value, pattern)"));
        Ok(())
    }

    #[test]
    fn rejects_multiple_top_level_json_values() {
        let err = build_json_output(br#"{} {}"#, JsonOutputOptions::default()).err();
        assert!(err.is_some());
    }

    #[test]
    fn jsonpath_no_match_returns_empty_array_for_requested_key() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"name":"api"}]}"#,
            JsonOutputOptions {
                max_bytes: 4096,
                json_paths: paths(&[
                    "$.items[*].missing",
                    "$.items[*].missing.length()",
                    "$.items[*].missing.count()",
                ]),
                ..JsonOutputOptions::default()
            },
        )?;

        assert!(!out.truncated);
        assert_eq!(
            out.body.get("$.items[*].missing"),
            Some(&serde_json::json!([]))
        );
        assert_eq!(
            out.body.get("$.items[*].missing.length()"),
            Some(&serde_json::json!([]))
        );
        assert_eq!(
            out.body.get("$.items[*].missing.count()"),
            Some(&serde_json::json!(0))
        );
        assert!(out.more.is_none());
        Ok(())
    }

    #[test]
    fn preview_escapes_non_dot_jsonpath_segments() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"weird-key":{"a.b":1},"quote'name":2}]}"#,
            JsonOutputOptions {
                max_bytes: 16,
                ..JsonOutputOptions::default()
            },
        )?;
        let more = out.more.ok_or_else(|| Error::internal("missing more"))?;
        let preview = more
            .preview
            .ok_or_else(|| Error::internal("missing preview"))?;
        let paths = preview
            .paths
            .into_iter()
            .map(|path| path.path)
            .collect::<Vec<_>>();

        assert!(
            paths
                .iter()
                .any(|path| path == "$.items[*]['weird-key']['a.b']")
        );
        assert!(
            paths
                .iter()
                .any(|path| path == r#"$.items[*]['quote\'name']"#)
        );
        Ok(())
    }

    #[test]
    fn preview_marks_nested_array_expansion_stopped() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"matrix":[[1,2],[3,4]]}]}"#,
            JsonOutputOptions {
                max_bytes: 16,
                ..JsonOutputOptions::default()
            },
        )?;
        let more = out.more.ok_or_else(|| Error::internal("missing more"))?;
        let preview = more
            .preview
            .ok_or_else(|| Error::internal("missing preview"))?;

        assert!(
            preview
                .paths
                .iter()
                .any(|path| { path.path == "$.items[*].matrix" && path.nested_expansion_stopped })
        );
        Ok(())
    }

    #[test]
    fn preview_caps_returned_paths() -> Result<()> {
        let mut object = Map::new();
        for idx in 0..40 {
            object.insert(format!("field_{idx:02}"), Value::from(idx));
        }
        let raw = serde_json::to_vec(&Value::Object(object))
            .map_err(|error| Error::internal(error.to_string()))?;
        let out = build_json_output(
            &raw,
            JsonOutputOptions {
                max_bytes: 16,
                ..JsonOutputOptions::default()
            },
        )?;
        let more = out.more.ok_or_else(|| Error::internal("missing more"))?;
        let preview = more
            .preview
            .ok_or_else(|| Error::internal("missing preview"))?;

        assert!(preview.path_count > MAX_PREVIEW_PATHS);
        assert!(preview.returned_paths <= MAX_PREVIEW_PATHS);
        assert!(preview.truncated);
        Ok(())
    }

    #[test]
    fn suggested_max_bytes_respects_max_allowed_bytes() -> Result<()> {
        let out = build_json_output(
            br#"{"items":[{"name":"api","phase":"Running"},{"name":"worker","phase":"Pending"}]}"#,
            JsonOutputOptions {
                max_bytes: 16,
                max_allowed_bytes: 32,
                ..JsonOutputOptions::default()
            },
        )?;
        let more = out.more.ok_or_else(|| Error::internal("missing more"))?;

        assert!(more.options.suggested_max_bytes <= Some(32));
        Ok(())
    }

    #[test]
    fn source_body_truncation_preserves_reported_original_size() -> Result<()> {
        let out = build_json_output(
            br#"{"partial":true}"#,
            JsonOutputOptions {
                source_body_truncated: true,
                original_bytes: Some(2048),
                ..JsonOutputOptions::default()
            },
        )?;
        assert!(out.truncated);
        assert_eq!(out.body_mode, BodyMode::RawJson);
        assert_eq!(out.body_state, BodyState::Omitted);
        assert_eq!(out.omit_reason, Some(OmitReason::Source));
        assert_eq!(out.original_bytes, 2048);
        assert_eq!(out.returned_bytes, 0);
        let more = out.more.ok_or_else(|| Error::internal("missing more"))?;
        assert_eq!(more.options.next_action, NextAction::NarrowRequest);
        assert_eq!(more.options.suggested_max_bytes, None);
        assert!(more.options.suggested_jsonpath.is_empty());
        assert!(more.preview.is_none());
        assert!(more.hints.iter().any(|hint| {
            hint.contains("could not read the full target response body")
                && hint.contains("pagination")
        }));
        Ok(())
    }

    #[test]
    fn source_body_truncation_requires_narrow_request_even_with_jsonpath() -> Result<()> {
        let out = build_json_output(
            br#"{"partial":true}"#,
            JsonOutputOptions {
                json_paths: vec!["$.partial".to_owned()],
                source_body_truncated: true,
                original_bytes: Some(2048),
                ..JsonOutputOptions::default()
            },
        )?;

        assert_eq!(out.body_mode, BodyMode::JsonpathProjection);
        assert_eq!(out.body_state, BodyState::Omitted);
        assert_eq!(out.omit_reason, Some(OmitReason::Source));
        let more = out.more.ok_or_else(|| Error::internal("missing more"))?;
        assert_eq!(more.options.next_action, NextAction::NarrowRequest);
        assert!(more.options.suggested_jsonpath.is_empty());
        assert_eq!(more.options.suggested_max_bytes, None);
        Ok(())
    }
}

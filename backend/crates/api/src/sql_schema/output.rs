use opsgate_core::{Error, Result};
use schemars::JsonSchema;
use serde::Serialize;

use super::input::{MAX_MAX_BYTES, MODE_TABLES, NormalizedInput};

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub(crate) struct SqlSchemaOutput {
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
pub(crate) struct TableSummary {
    pub namespace: String,
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub(crate) struct TableDetail {
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
pub(crate) struct Column {
    pub name: String,
    #[serde(rename = "type")]
    pub data_type: String,
    pub nullable: bool,
    #[serde(skip_serializing_if = "is_false", default)]
    pub has_default: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub(crate) struct Index {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
    #[serde(skip_serializing_if = "is_false", default)]
    pub primary: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub(crate) struct Page {
    pub limit: i32,
    pub returned: usize,
    pub has_more: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub next_cursor: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub(crate) struct More {
    pub options: MoreOption,
    pub hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub(crate) struct MoreOption {
    #[serde(skip_serializing_if = "is_false", default)]
    pub retry_without_indexes: bool,
    #[serde(skip_serializing_if = "is_false", default)]
    pub use_table_mode: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_max_bytes: Option<usize>,
}

pub(super) fn finalize_output(out: &mut SqlSchemaOutput, input: &NormalizedInput) -> Result<()> {
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

pub(super) fn join_cursor(namespace: &str, table: &str) -> String {
    format!("{namespace}.{table}")
}

fn is_false(value: &bool) -> bool {
    !*value
}

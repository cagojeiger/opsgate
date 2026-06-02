use opsgate_core::{Error, Result};
use schemars::JsonSchema;
use serde::Serialize;

use super::input::{MAX_MAX_BYTES, MODE_TABLES, NormalizedInput};

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

#[cfg(test)]
mod tests {
    use super::*;

    fn input(max_bytes: usize) -> NormalizedInput {
        NormalizedInput {
            alias: "analytics".to_owned(),
            purpose: "Inspect schema safely".to_owned(),
            database: None,
            mode: MODE_TABLES.to_owned(),
            namespace: String::new(),
            table: String::new(),
            limit: 50,
            cursor: String::new(),
            max_bytes,
            timeout_ms: 3000,
            include_indexes: true,
        }
    }

    #[test]
    fn table_detail_trimming_drops_indexes_before_columns() -> Result<()> {
        let mut output = SqlSchemaOutput {
            mode: "table".to_owned(),
            tables: Vec::new(),
            table: Some(TableDetail {
                namespace: "public".to_owned(),
                name: "audit_logs".to_owned(),
                kind: "table".to_owned(),
                columns: vec![Column {
                    name: "id".to_owned(),
                    data_type: "bigint".to_owned(),
                    nullable: false,
                    has_default: true,
                }],
                primary_key: vec!["id".to_owned()],
                indexes: vec![Index {
                    name: "audit_logs_created_at_idx".repeat(8),
                    columns: vec!["created_at".to_owned()],
                    unique: false,
                    primary: false,
                }],
            }),
            page: None,
            truncated: false,
            returned_bytes: 0,
            more: None,
            latency_ms: 3,
        };
        let mut limit_input = input(1024);
        output.returned_bytes = encoded_len(&output)?;
        limit_input.max_bytes = output.returned_bytes - 1;

        finalize_output(&mut output, &limit_input)?;

        let table = output
            .table
            .as_ref()
            .ok_or_else(|| Error::internal("missing table"))?;
        assert!(output.truncated);
        assert!(table.indexes.is_empty());
        assert_eq!(table.columns.len(), 1);
        assert_eq!(table.primary_key, vec!["id".to_owned()]);
        assert!(output.returned_bytes <= limit_input.max_bytes);
        Ok(())
    }

    #[test]
    fn table_list_trimming_marks_page_has_more() -> Result<()> {
        let mut output = SqlSchemaOutput {
            mode: MODE_TABLES.to_owned(),
            tables: vec![
                TableSummary {
                    namespace: "public".to_owned(),
                    name: "short".to_owned(),
                    kind: "table".to_owned(),
                },
                TableSummary {
                    namespace: "public".to_owned(),
                    name: "very_long_table_name_".repeat(10),
                    kind: "table".to_owned(),
                },
            ],
            table: None,
            page: Some(Page {
                limit: 50,
                returned: 2,
                has_more: false,
                next_cursor: String::new(),
            }),
            truncated: false,
            returned_bytes: 0,
            more: None,
            latency_ms: 2,
        };
        output.returned_bytes = encoded_len(&output)?;
        let first_table = output
            .tables
            .first()
            .cloned()
            .ok_or_else(|| Error::internal("missing first table"))?;
        let max_bytes = encoded_len(&SqlSchemaOutput {
            tables: vec![first_table],
            page: Some(Page {
                limit: 50,
                returned: 1,
                has_more: true,
                next_cursor: "public.short".to_owned(),
            }),
            ..output.clone()
        })?;

        trim_table_list(&mut output, max_bytes)?;

        let page = output
            .page
            .as_ref()
            .ok_or_else(|| Error::internal("missing page"))?;
        assert_eq!(output.tables.len(), 1);
        assert!(page.has_more);
        assert_eq!(page.returned, 1);
        assert_eq!(page.next_cursor, "public.short");
        assert!(output.returned_bytes <= max_bytes);
        Ok(())
    }

    #[test]
    fn suggested_max_bytes_is_capped() -> Result<()> {
        let mut output = SqlSchemaOutput {
            mode: MODE_TABLES.to_owned(),
            tables: vec![TableSummary {
                namespace: "public".to_owned(),
                name: "large_table_".repeat(120_000),
                kind: "table".to_owned(),
            }],
            table: None,
            page: Some(Page {
                limit: 50,
                returned: 1,
                has_more: false,
                next_cursor: String::new(),
            }),
            truncated: false,
            returned_bytes: 0,
            more: None,
            latency_ms: 1,
        };
        let limit_input = input(MAX_MAX_BYTES - 1);

        finalize_output(&mut output, &limit_input)?;

        let more = output.more.ok_or_else(|| Error::internal("missing more"))?;
        assert_eq!(more.options.suggested_max_bytes, Some(MAX_MAX_BYTES));
        Ok(())
    }
}

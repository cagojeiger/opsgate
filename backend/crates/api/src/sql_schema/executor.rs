use opsgate_core::{Error, Result};
use sqlx::{FromRow, PgConnection};

use crate::sql_common::SqlSecret;

use super::input::{MODE_TABLE, MODE_TABLES, NormalizedInput};
use super::output::{Column, Index, Page, SqlSchemaOutput, TableDetail, TableSummary, join_cursor};

pub(super) async fn execute_schema_query(
    pools: &crate::target::pg_pool::TargetPgPools,
    credential_id: uuid::Uuid,
    target: &crate::target::postgres::GuardedPostgresTarget,
    secret: &SqlSecret,
    input: &NormalizedInput,
) -> Result<SqlSchemaOutput> {
    let mut conn = crate::sql_common::begin_read_only_connection(
        pools,
        credential_id,
        target,
        secret,
        input.timeout_ms,
    )
    .await?;
    let result = if input.mode == MODE_TABLE {
        load_table(&mut conn, input).await
    } else {
        list_tables(&mut conn, input).await
    };
    crate::sql_common::finish_read_only_result(&mut conn, result).await
}

async fn list_tables(conn: &mut PgConnection, input: &NormalizedInput) -> Result<SqlSchemaOutput> {
    let (cursor_ns, cursor_table) = split_cursor(&input.cursor);
    let rows = sqlx::query_as::<_, TableRow>(
        r#"
        SELECT table_schema AS namespace, table_name AS name, table_type
        FROM information_schema.tables
        WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
          AND table_type IN ('BASE TABLE', 'VIEW')
          AND (($1 = '' AND $2 = '') OR (table_schema, table_name) > ($1, $2))
        ORDER BY table_schema, table_name
        LIMIT $3
        "#,
    )
    .bind(cursor_ns)
    .bind(cursor_table)
    .bind(input.limit + 1)
    .fetch_all(conn)
    .await
    .map_err(|error| {
        crate::sql_common::map_postgres_schema_error(error, "postgres schema table list failed")
    })?;

    let mut tables = Vec::new();
    let mut page = Page {
        limit: input.limit,
        returned: 0,
        has_more: false,
        next_cursor: String::new(),
    };
    for row in rows {
        if tables.len() >= usize::try_from(input.limit).unwrap_or(usize::MAX) {
            page.has_more = true;
            continue;
        }
        page.next_cursor = join_cursor(&row.namespace, &row.name);
        tables.push(TableSummary {
            namespace: row.namespace,
            name: row.name,
            kind: table_kind(&row.table_type).to_owned(),
        });
    }
    page.returned = tables.len();
    if !page.has_more {
        page.next_cursor.clear();
    }
    Ok(SqlSchemaOutput {
        mode: MODE_TABLES.to_owned(),
        tables,
        table: None,
        page: Some(page),
        truncated: false,
        returned_bytes: 0,
        more: None,
        latency_ms: 0,
    })
}

async fn load_table(conn: &mut PgConnection, input: &NormalizedInput) -> Result<SqlSchemaOutput> {
    let (columns, kind) = load_columns(conn, &input.namespace, &input.table).await?;
    let mut detail = TableDetail {
        namespace: input.namespace.clone(),
        name: input.table.clone(),
        kind,
        columns,
        primary_key: load_primary_key(conn, &input.namespace, &input.table).await?,
        indexes: Vec::new(),
    };
    if detail.columns.is_empty() {
        return Err(Error::not_found(
            "table not found or has no visible columns",
        ));
    }
    if input.include_indexes {
        detail.indexes = load_indexes(conn, &input.namespace, &input.table).await?;
    }
    Ok(SqlSchemaOutput {
        mode: MODE_TABLE.to_owned(),
        tables: Vec::new(),
        table: Some(detail),
        page: None,
        truncated: false,
        returned_bytes: 0,
        more: None,
        latency_ms: 0,
    })
}

async fn load_columns(
    conn: &mut PgConnection,
    namespace: &str,
    table: &str,
) -> Result<(Vec<Column>, String)> {
    let rows = sqlx::query_as::<_, ColumnRow>(
        r#"
        SELECT a.attname AS name,
               pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
               NOT a.attnotnull AS nullable,
               ad.oid IS NOT NULL AS has_default,
               c.relkind::text AS relation_kind
        FROM pg_catalog.pg_attribute a
        JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        WHERE n.nspname = $1
          AND c.relname = $2
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND a.attnum > 0
          AND NOT a.attisdropped
        ORDER BY a.attnum
        "#,
    )
    .bind(namespace)
    .bind(table)
    .fetch_all(conn)
    .await
    .map_err(|error| {
        crate::sql_common::map_postgres_schema_error(error, "postgres schema column lookup failed")
    })?;
    let mut kind = "table".to_owned();
    let columns = rows
        .into_iter()
        .map(|row| {
            kind = relation_kind(&row.relation_kind).to_owned();
            Column {
                name: row.name,
                data_type: row.data_type,
                nullable: row.nullable,
                has_default: row.has_default,
            }
        })
        .collect();
    Ok((columns, kind))
}

async fn load_primary_key(
    conn: &mut PgConnection,
    namespace: &str,
    table: &str,
) -> Result<Vec<String>> {
    let joined = sqlx::query_scalar::<_, String>(
        r#"
        SELECT COALESCE(array_to_string(array_agg(a.attname ORDER BY ord.n), ','), '')
        FROM pg_catalog.pg_class t
        JOIN pg_catalog.pg_namespace ns ON ns.oid = t.relnamespace
        JOIN pg_catalog.pg_index ix ON ix.indrelid = t.oid AND ix.indisprimary
        JOIN unnest(ix.indkey) WITH ORDINALITY AS ord(attnum, n) ON true
        JOIN pg_catalog.pg_attribute a ON a.attrelid = t.oid AND a.attnum = ord.attnum
        WHERE ns.nspname = $1 AND t.relname = $2
        "#,
    )
    .bind(namespace)
    .bind(table)
    .fetch_one(conn)
    .await
    .map_err(|error| {
        crate::sql_common::map_postgres_schema_error(
            error,
            "postgres schema primary key lookup failed",
        )
    })?;
    Ok(split_comma_list(&joined))
}

async fn load_indexes(conn: &mut PgConnection, namespace: &str, table: &str) -> Result<Vec<Index>> {
    let rows = sqlx::query_as::<_, IndexRow>(
        r#"
        SELECT ci.relname AS name,
               ix.indisunique AS unique,
               ix.indisprimary AS primary,
               COALESCE(array_to_string(array_agg(a.attname ORDER BY ord.n) FILTER (WHERE a.attname IS NOT NULL), ','), '') AS columns
        FROM pg_catalog.pg_class t
        JOIN pg_catalog.pg_namespace ns ON ns.oid = t.relnamespace
        JOIN pg_catalog.pg_index ix ON ix.indrelid = t.oid
        JOIN pg_catalog.pg_class ci ON ci.oid = ix.indexrelid
        JOIN unnest(ix.indkey) WITH ORDINALITY AS ord(attnum, n) ON true
        LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = t.oid AND a.attnum = ord.attnum
        WHERE ns.nspname = $1 AND t.relname = $2
        GROUP BY ci.relname, ix.indisunique, ix.indisprimary
        ORDER BY ix.indisprimary DESC, ci.relname
        "#,
    )
    .bind(namespace)
    .bind(table)
    .fetch_all(conn)
    .await
    .map_err(|error| {
        crate::sql_common::map_postgres_schema_error(error, "postgres schema index lookup failed")
    })?;
    Ok(rows
        .into_iter()
        .map(|row| Index {
            name: row.name,
            columns: split_comma_list(&row.columns),
            unique: row.unique,
            primary: row.primary,
        })
        .collect())
}

#[derive(Debug, FromRow)]
struct TableRow {
    namespace: String,
    name: String,
    table_type: String,
}

#[derive(Debug, FromRow)]
struct ColumnRow {
    name: String,
    data_type: String,
    nullable: bool,
    has_default: bool,
    relation_kind: String,
}

#[derive(Debug, FromRow)]
struct IndexRow {
    name: String,
    unique: bool,
    primary: bool,
    columns: String,
}

fn split_cursor(cursor: &str) -> (String, String) {
    if let Some((namespace, table)) = cursor.split_once('.') {
        return (namespace.to_owned(), table.to_owned());
    }
    (String::new(), cursor.to_owned())
}

fn table_kind(table_type: &str) -> &'static str {
    if table_type.trim().eq_ignore_ascii_case("VIEW") {
        "view"
    } else {
        "table"
    }
}

fn relation_kind(kind: &str) -> &'static str {
    match kind {
        "v" => "view",
        "m" => "materialized_view",
        "f" => "foreign_table",
        "p" => "partitioned_table",
        _ => "table",
    }
}

fn split_comma_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

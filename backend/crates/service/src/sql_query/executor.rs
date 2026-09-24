use opsgate_core::{Error, Result};
use serde_json::Value;
use sqlx::PgConnection;
use sqlx::types::Json;

use crate::sql_common::SqlSecret;

use super::input::NormalizedInput;
use super::output::{SqlQueryOutput, build_column_output};
use super::policy::QueryAnalysis;

pub(super) async fn execute_postgres(
    pools: &opsgate_infra::postgres_pool::TargetPgPools,
    credential_id: uuid::Uuid,
    target: &opsgate_infra::postgres::GuardedPostgresTarget,
    secret: &SqlSecret,
    input: &NormalizedInput,
    analysis: QueryAnalysis,
) -> Result<SqlQueryOutput> {
    let mut conn = crate::sql_common::begin_read_only_connection(
        pools,
        credential_id,
        target,
        secret,
        input.database.as_deref(),
        input.timeout_ms,
    )
    .await?;
    let result = if analysis.is_explain {
        load_explain_rows(&mut conn, input, analysis).await
    } else {
        load_rows(&mut conn, input, analysis).await
    };
    crate::sql_common::finish_read_only_result(&mut conn, result).await
}

async fn load_explain_rows(
    conn: &mut PgConnection,
    input: &NormalizedInput,
    analysis: QueryAnalysis,
) -> Result<SqlQueryOutput> {
    let mut query = sqlx::query_scalar::<_, String>(&input.query);
    for param in &input.params {
        query = bind_string_param(query, param)?;
    }
    let mut plans = query
        .fetch_all(conn)
        .await
        .map_err(crate::sql_common::map_postgres_query_error)?;
    let mut truncated = false;
    if plans.len() > usize::try_from(input.max_rows).unwrap_or(usize::MAX) {
        plans.truncate(usize::try_from(input.max_rows).unwrap_or(usize::MAX));
        truncated = true;
    }
    let rows = plans
        .into_iter()
        .map(|line| serde_json::json!({"QUERY PLAN": line}))
        .collect();
    build_column_output(rows, input, truncated, analysis)
}

async fn load_rows(
    conn: &mut PgConnection,
    input: &NormalizedInput,
    analysis: QueryAnalysis,
) -> Result<SqlQueryOutput> {
    let limit = input.max_rows + 1;
    let wrapped = format!(
        "SELECT COALESCE(json_agg(row_to_json(opsgate_limited)), '[]'::json) AS rows FROM (SELECT * FROM ({}) AS opsgate_q LIMIT {}) AS opsgate_limited",
        input.query, limit
    );
    let mut query = sqlx::query_scalar::<_, Value>(&wrapped);
    for param in &input.params {
        query = bind_json_param(query, param)?;
    }
    let value = query
        .fetch_one(conn)
        .await
        .map_err(crate::sql_common::map_postgres_query_error)?;
    // json_agg always yields an array; move it out instead of cloning the rows.
    let mut rows = match value {
        Value::Array(rows) => rows,
        _ => Vec::new(),
    };
    let mut truncated = false;
    if rows.len() > usize::try_from(input.max_rows).unwrap_or(usize::MAX) {
        rows.truncate(usize::try_from(input.max_rows).unwrap_or(usize::MAX));
        truncated = true;
    }
    build_column_output(rows, input, truncated, analysis)
}

fn bind_string_param<'q>(
    query: sqlx::query::QueryScalar<'q, sqlx::Postgres, String, sqlx::postgres::PgArguments>,
    value: &Value,
) -> Result<sqlx::query::QueryScalar<'q, sqlx::Postgres, String, sqlx::postgres::PgArguments>> {
    let query = match value {
        Value::Null => query.bind(Option::<String>::None),
        Value::Bool(value) => query.bind(*value),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                query.bind(value)
            } else if let Some(value) = number.as_u64() {
                let value = i64::try_from(value)
                    .map_err(|_error| Error::validation("numeric param out of range"))?;
                query.bind(value)
            } else if let Some(value) = number.as_f64() {
                query.bind(value)
            } else {
                return Err(Error::validation("invalid numeric param"));
            }
        }
        Value::String(value) => query.bind(value.clone()),
        Value::Array(_) | Value::Object(_) => query.bind(Json(value.clone())),
    };
    Ok(query)
}

fn bind_json_param<'q>(
    query: sqlx::query::QueryScalar<'q, sqlx::Postgres, Value, sqlx::postgres::PgArguments>,
    value: &Value,
) -> Result<sqlx::query::QueryScalar<'q, sqlx::Postgres, Value, sqlx::postgres::PgArguments>> {
    let query = match value {
        Value::Null => query.bind(Option::<String>::None),
        Value::Bool(value) => query.bind(*value),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                query.bind(value)
            } else if let Some(value) = number.as_u64() {
                let value = i64::try_from(value)
                    .map_err(|_error| Error::validation("numeric param out of range"))?;
                query.bind(value)
            } else if let Some(value) = number.as_f64() {
                query.bind(value)
            } else {
                return Err(Error::validation("invalid numeric param"));
            }
        }
        Value::String(value) => query.bind(value.clone()),
        Value::Array(_) | Value::Object(_) => query.bind(Json(value.clone())),
    };
    Ok(query)
}

#[cfg(test)]
mod tests {
    use opsgate_model::credential::CredentialPolicy;

    use super::*;
    use crate::sql_query::input::{SqlQueryInput, normalize_input};
    use crate::sql_query::policy::enforce_sql_policy;

    #[tokio::test]
    async fn executes_analyzed_queries() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let database_url = match std::env::var("OPSGATE_TEST_DATABASE_MIGRATE_URL") {
            Ok(value) if !value.trim().is_empty() => value,
            _ if std::env::var("CI").is_ok_and(|value| value == "true") => {
                return Err(
                    "OPSGATE_TEST_DATABASE_MIGRATE_URL must be set for PostgreSQL tests in CI"
                        .into(),
                );
            }
            _ => {
                eprintln!(
                    "skipping PostgreSQL executor test; set OPSGATE_TEST_DATABASE_MIGRATE_URL to run it"
                );
                return Ok(());
            }
        };
        let mut url = url::Url::parse(&database_url)?;
        let secret = SqlSecret {
            username: url.username().to_owned().into(),
            password: url.password().unwrap_or_default().to_owned().into(),
        };
        url.set_password(None)
            .map_err(|()| "invalid test database URL")?;
        url.set_username("")
            .map_err(|()| "invalid test database URL")?;
        let target =
            opsgate_infra::postgres::prepare_postgres_target(url.as_str(), true, true).await?;
        let pools = opsgate_infra::postgres_pool::TargetPgPools::new();
        let credential_id = uuid::Uuid::new_v4();
        let policy = CredentialPolicy {
            allow_explain: true,
            ..CredentialPolicy::default()
        };
        for (query, column, wildcard_hint) in [
            ("EXPLAIN SELECT 1", "QUERY PLAN", false),
            ("/* caller comment */ EXPLAIN SELECT 1", "QUERY PLAN", false),
            ("-- caller comment\nexplain select 1", "QUERY PLAN", false),
            ("/* caller comment */ SELECT 1 AS id", "id", false),
            ("SELECT * FROM (VALUES (1)) AS t(id)", "id", true),
            (
                "/* caller comment */ EXPLAIN SELECT * FROM (VALUES (1)) AS t(id)",
                "QUERY PLAN",
                true,
            ),
        ] {
            let input = normalize_input(SqlQueryInput {
                alias: "executor-test".to_owned(),
                purpose: "Verify analyzed SQL execution".to_owned(),
                database: None,
                query: query.to_owned(),
                params: Vec::new(),
                jsonpath: Vec::new(),
                max_rows: None,
                max_bytes: None,
                timeout_ms: None,
            })?;
            let analysis = enforce_sql_policy(&input.query, &policy)?;
            let output =
                execute_postgres(&pools, credential_id, &target, &secret, &input, analysis).await?;
            assert!(output.row_count > 0, "{query}");
            assert!(output.body.get(column).is_some(), "{query}");
            assert_eq!(!output.hints.is_empty(), wildcard_hint, "{query}");
        }
        Ok(())
    }

    #[test]
    fn bind_params_allow_json_array_and_object_values() -> Result<()> {
        let array_param = serde_json::json!(["paid", "failed"]);
        let object_param = serde_json::json!({"status": "paid"});

        let query = sqlx::query_scalar::<_, Value>("select $1");
        assert!(bind_json_param(query, &array_param).is_ok());
        let query = sqlx::query_scalar::<_, String>("explain select $1");
        assert!(bind_string_param(query, &object_param).is_ok());
        Ok(())
    }
}

use opsgate_core::Error;

pub(crate) fn map_postgres_query_error(error: sqlx::Error) -> Error {
    map_postgres_error(error, "sql query failed")
}

pub(crate) fn map_postgres_schema_error(error: sqlx::Error, fallback: &'static str) -> Error {
    map_postgres_error(error, fallback)
}

pub(crate) fn safe_error_record(
    error: &Error,
    fallback_kind: &'static str,
    fallback_message: &'static str,
) -> (&'static str, String) {
    match error {
        Error::UserSafe { kind, message, .. } => (*kind, message.clone()),
        Error::NotFound(message) | Error::Forbidden(message) | Error::Validation(message) => {
            (fallback_kind, message.clone())
        }
        Error::Internal(_message) => (fallback_kind, fallback_message.to_owned()),
    }
}

fn map_postgres_error(error: sqlx::Error, fallback: &'static str) -> Error {
    if let Some(error) = error.as_database_error()
        && let Some(code) = error.code()
        && let Some(mapped) = error_from_sqlstate(&code)
    {
        return mapped;
    }
    Error::internal(fallback)
}

fn error_from_sqlstate(code: &str) -> Option<Error> {
    let (kind, message, hint) = match code {
        "42601" => (
            "sql_syntax_error",
            "SQL syntax is invalid.",
            "Rewrite the query as one read-only SELECT/WITH statement.",
        ),
        "42703" => (
            "sql_undefined_column",
            "SQL references a column that does not exist.",
            "Use sql.schema(mode=\"table\") for the target table, then retry with existing columns.",
        ),
        "42P01" => (
            "sql_undefined_table",
            "SQL references a table or relation that does not exist.",
            "Use sql.schema(mode=\"tables\") to list visible tables, then sql.schema(mode=\"table\") before retrying.",
        ),
        "42702" => (
            "sql_ambiguous_column",
            "SQL has an ambiguous column reference.",
            "Qualify the column with its table or subquery alias.",
        ),
        "42883" => (
            "sql_undefined_function",
            "SQL calls a function that does not exist or is unavailable.",
            "Check the function name and argument types, or avoid the function.",
        ),
        "42P02" => (
            "sql_undefined_parameter",
            "SQL references a bind parameter that was not provided.",
            "Provide all positional params used by the query.",
        ),
        "22P02" => (
            "sql_invalid_parameter",
            "A SQL parameter value cannot be cast to the expected type.",
            "Check the params array and use values matching the target column types.",
        ),
        "42804" => (
            "sql_datatype_mismatch",
            "SQL uses values with incompatible data types.",
            "Cast explicitly or adjust params to match the target column types.",
        ),
        "42501" => (
            "sql_permission_denied",
            "The target database role does not have permission for this SQL operation.",
            "Use sql.schema to confirm visible objects, or register a credential with the required read grants.",
        ),
        "57014" => (
            "sql_timeout_or_canceled",
            "SQL execution was canceled or timed out.",
            "Narrow the query with WHERE, aggregate with count/group, or lower the scanned row set.",
        ),
        _ => return None,
    };
    Some(Error::user_safe(kind, message, Some(hint)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlstate_mapping_exposes_safe_actionable_errors() -> Result<(), String> {
        let error = error_from_sqlstate("42703")
            .ok_or_else(|| "undefined column should be mapped".to_owned())?;
        let Error::UserSafe {
            kind,
            message,
            hint,
        } = error
        else {
            return Err("expected user-safe error".to_owned());
        };
        assert_eq!(kind, "sql_undefined_column");
        assert!(message.contains("column"));
        assert!(
            hint.as_deref()
                .is_some_and(|hint| hint.contains("sql.schema"))
        );
        Ok(())
    }

    #[test]
    fn sqlstate_mapping_rejects_unknown_codes() {
        assert!(error_from_sqlstate("99999").is_none());
    }

    #[test]
    fn safe_error_record_keeps_internal_errors_generic() {
        let error = Error::internal("driver returned target secret");
        let (kind, message) = safe_error_record(&error, "query_failed", "sql query failed");
        assert_eq!(kind, "query_failed");
        assert_eq!(message, "sql query failed");
    }
}

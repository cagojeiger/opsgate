use std::ops::ControlFlow;

use opsgate_core::{Error, Result};
use opsgate_model::credential::CredentialPolicy;
use sqlparser::ast::{
    Expr, ObjectName, Query, Select, SelectItem, SetExpr, Statement, Visit, Visitor,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use super::input::NormalizedInput;

const BUILTIN_DENIED_FUNCTIONS: &[&str] = &[
    "dblink",
    "lo_export",
    "lo_import",
    "pg_advisory_lock",
    "pg_advisory_xact_lock",
    "pg_cancel_backend",
    "pg_read_binary_file",
    "pg_read_file",
    "pg_sleep",
    "pg_terminate_backend",
    "set_config",
];

pub(super) fn validate_policy_boundary(
    policy: &CredentialPolicy,
    input: &NormalizedInput,
) -> Result<()> {
    if policy.allow_explain_analyze && !policy.allow_explain {
        return Err(Error::validation("sql policy is invalid"));
    }
    if policy.max_rows > 0 && input.max_rows > i32::try_from(policy.max_rows).unwrap_or(i32::MAX) {
        return Err(Error::validation("max_rows exceeds credential policy"));
    }
    if policy.max_bytes > 0
        && input.max_bytes > usize::try_from(policy.max_bytes).unwrap_or(usize::MAX)
    {
        return Err(Error::validation("max_bytes exceeds credential policy"));
    }
    if policy.timeout_ms > 0 && input.timeout_ms > policy.timeout_ms {
        return Err(Error::validation("timeout_ms exceeds credential policy"));
    }
    Ok(())
}

pub(super) fn enforce_sql_policy(query: &str, policy: &CredentialPolicy) -> Result<()> {
    let dialect = PostgreSqlDialect {};
    let statements = Parser::parse_sql(&dialect, query)
        .map_err(|error| Error::validation(format!("query has SQL syntax error: {error}")))?;
    if statements.len() != 1 {
        return Err(Error::validation(format!(
            "query must contain exactly one statement, got {}",
            statements.len()
        )));
    }
    let statement = statements
        .first()
        .ok_or_else(|| Error::validation("query statement is empty"))?;
    match statement {
        Statement::Query(query) => validate_query_ast(query),
        Statement::Explain {
            analyze, statement, ..
        } => {
            if !policy.allow_explain {
                return Err(Error::validation(
                    "EXPLAIN is not allowed by credential policy",
                ));
            }
            if *analyze && !policy.allow_explain_analyze {
                return Err(Error::validation(
                    "EXPLAIN ANALYZE is not allowed by credential policy",
                ));
            }
            match statement.as_ref() {
                Statement::Query(query) => validate_query_ast(query),
                _ => Err(Error::validation(
                    "EXPLAIN is only allowed for SELECT/WITH queries",
                )),
            }
        }
        _ => Err(Error::validation(
            "query must be a single SELECT/WITH statement or policy-approved EXPLAIN",
        )),
    }?;
    enforce_ast_policy(statement, policy)
}

fn validate_query_ast(query: &Query) -> Result<()> {
    if !query.locks.is_empty() {
        return Err(Error::validation("SELECT locking clauses are not allowed"));
    }
    // Reject data-modifying CTEs (`WITH x AS (INSERT ... RETURNING) ...`) at the
    // policy layer instead of relying on the BEGIN READ ONLY runtime backstop.
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            validate_query_ast(&cte.query)?;
        }
    }
    validate_set_expr(&query.body)
}

fn validate_set_expr(expr: &SetExpr) -> Result<()> {
    match expr {
        SetExpr::Select(select) => {
            if select.into.is_some() {
                return Err(Error::validation("SELECT INTO is not allowed"));
            }
            Ok(())
        }
        SetExpr::Query(query) => validate_query_ast(query),
        SetExpr::SetOperation { left, right, .. } => {
            validate_set_expr(left)?;
            validate_set_expr(right)
        }
        _ => Err(Error::validation(
            "query contains a statement type that sql_query does not allow",
        )),
    }
}

pub(super) fn query_uses_select_wildcard(query: &str) -> bool {
    let dialect = PostgreSqlDialect {};
    let Ok(statements) = Parser::parse_sql(&dialect, query) else {
        return false;
    };
    let mut visitor = SelectWildcardVisitor { found: false };
    for statement in statements {
        let _ = statement.visit(&mut visitor);
        if visitor.found {
            return true;
        }
    }
    false
}

struct SelectWildcardVisitor {
    found: bool,
}

impl Visitor for SelectWildcardVisitor {
    type Break = ();

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<Self::Break> {
        if select.projection.iter().any(|item| {
            matches!(
                item,
                SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(_, _)
            )
        }) {
            self.found = true;
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// Enforce metadata/function denials on the parsed AST rather than the raw
/// query text. Walking real syntax nodes is immune to whitespace/quoting
/// evasions (e.g. `pg_sleep (10)`, `pg_catalog .pg_tables`) and avoids false
/// positives on legitimate `pg_`-prefixed identifiers used outside relations.
fn enforce_ast_policy(statement: &Statement, policy: &CredentialPolicy) -> Result<()> {
    let mut visitor = SqlPolicyVisitor {
        policy,
        violation: None,
    };
    let _ = statement.visit(&mut visitor);
    match visitor.violation {
        Some(message) => Err(Error::validation(message)),
        None => Ok(()),
    }
}

struct SqlPolicyVisitor<'a> {
    policy: &'a CredentialPolicy,
    violation: Option<String>,
}

impl Visitor for SqlPolicyVisitor<'_> {
    type Break = ();

    fn pre_visit_relation(&mut self, name: &ObjectName) -> ControlFlow<Self::Break> {
        if !self.policy.allow_metadata && is_metadata_relation(name) {
            self.violation =
                Some("Postgres metadata access is not allowed by credential policy".to_owned());
            return ControlFlow::Break(());
        }
        // A table function (`FROM dblink(...)`) surfaces here as a relation name,
        // never as `Expr::Function`, so apply the function denylist to it too.
        self.check_function_name(name, true)
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        match expr {
            // Function calls (`pg_sleep(...)`): match on the parsed call name.
            Expr::Function(function) => self.check_function_name(&function.name, true),
            // Niladic value functions (`current_user`) may parse as identifiers;
            // only the credential's denylist applies (not the builtin call list).
            Expr::Identifier(ident) => {
                let candidate = ident.value.trim().to_ascii_lowercase();
                self.check_function_candidates(&candidate, &candidate, false)
            }
            Expr::CompoundIdentifier(parts) => match parts.last() {
                Some(ident) => {
                    let candidate = ident.value.trim().to_ascii_lowercase();
                    self.check_function_candidates(&candidate, &candidate, false)
                }
                None => ControlFlow::Continue(()),
            },
            _ => ControlFlow::Continue(()),
        }
    }
}

impl SqlPolicyVisitor<'_> {
    fn check_function_name(&mut self, name: &ObjectName, is_call: bool) -> ControlFlow<()> {
        let parts = object_name_parts(name);
        let Some(short) = parts.last() else {
            return ControlFlow::Continue(());
        };
        if is_call
            && !self.policy.allow_metadata
            && parts.len() > 1
            && let Some(schema) = parts.first().filter(|schema| is_metadata_schema(schema))
        {
            self.violation = Some(format!(
                "function schema {schema:?} is not allowed by credential policy"
            ));
            return ControlFlow::Break(());
        }
        let full = parts.join(".");
        self.check_function_candidates(&full, short, is_call)
    }

    /// Check a function/relation name against the builtin (call sites only) and
    /// credential-policy denylists, recording the first violation.
    fn check_function_candidates(
        &mut self,
        full_candidate: &str,
        short_candidate: &str,
        is_call: bool,
    ) -> ControlFlow<()> {
        if is_call
            && BUILTIN_DENIED_FUNCTIONS
                .iter()
                .any(|denied| denied == &short_candidate || denied == &full_candidate)
        {
            self.violation = Some(format!(
                "function {full_candidate:?} is blocked by built-in SQL policy"
            ));
            return ControlFlow::Break(());
        }
        if self.denied_policy_function(full_candidate, short_candidate) {
            self.violation = Some(format!(
                "function {full_candidate:?} is denied by credential policy"
            ));
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }

    /// Match Go parity: unqualified denied names match any schema, while
    /// qualified denied names match only the exact full call name.
    fn denied_policy_function(&self, full_candidate: &str, short_candidate: &str) -> bool {
        self.policy
            .denied_functions
            .iter()
            .map(|denied| denied.trim().to_ascii_lowercase())
            .any(|denied| {
                if denied.is_empty() {
                    false
                } else if denied.contains('.') {
                    denied == full_candidate
                } else {
                    denied == short_candidate
                }
            })
    }
}

/// Postgres catalog/metadata relation: schema-qualified `pg_catalog`/
/// `information_schema`, or an unqualified `pg_`-prefixed catalog table.
fn is_metadata_relation(name: &ObjectName) -> bool {
    let parts = object_name_parts(name);
    match parts.as_slice() {
        [] => false,
        [table] => table.starts_with("pg_"),
        [.., schema, _table] => is_metadata_schema(schema),
    }
}

fn object_name_parts(name: &ObjectName) -> Vec<String> {
    name.0
        .iter()
        .filter_map(|part| part.as_ident())
        .map(|ident| ident.value.trim().to_ascii_lowercase())
        .collect()
}

fn is_metadata_schema(schema: &str) -> bool {
    matches!(schema, "pg_catalog" | "information_schema")
}

#[cfg(test)]
mod tests {
    use opsgate_model::credential::CredentialPolicy;

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
    fn policy_boundary_rejects_budget_overrides() -> Result<()> {
        let policy = CredentialPolicy {
            max_rows: 10,
            max_bytes: 2048,
            timeout_ms: 1000,
            ..CredentialPolicy::default()
        };
        let mut input = input();
        input.max_rows = 11;
        assert!(validate_policy_boundary(&policy, &input).is_err());
        input.max_rows = 10;
        input.max_bytes = 4096;
        assert!(validate_policy_boundary(&policy, &input).is_err());
        input.max_bytes = 2048;
        input.timeout_ms = 1001;
        assert!(validate_policy_boundary(&policy, &input).is_err());
        Ok(())
    }

    #[test]
    fn detects_select_wildcard_for_output_hint() {
        assert!(query_uses_select_wildcard("select * from payments"));
        assert!(query_uses_select_wildcard("select p.* from payments p"));
        assert!(query_uses_select_wildcard(
            "with recent as (select * from payments) select id from recent"
        ));
        assert!(!query_uses_select_wildcard(
            "select id, status from payments"
        ));
        assert!(!query_uses_select_wildcard(
            "select '* not a projection' as literal"
        ));
    }

    #[test]
    fn ast_policy_allows_select_and_with() {
        let policy = CredentialPolicy::default();
        assert!(enforce_sql_policy("select 1", &policy).is_ok());
        assert!(
            enforce_sql_policy("select * from payments where created_at >= $1", &policy).is_ok()
        );
        assert!(enforce_sql_policy("with x as (select 1) select * from x", &policy).is_ok());
    }

    #[test]
    fn ast_policy_rejects_write_lock_metadata_and_functions() {
        let policy = CredentialPolicy::default();
        assert!(enforce_sql_policy("delete from users", &policy).is_err());
        assert!(enforce_sql_policy("select * from users for update", &policy).is_err());
        assert!(enforce_sql_policy("select pg_sleep(10)", &policy).is_err());
        assert!(enforce_sql_policy("select * from pg_catalog.pg_tables", &policy).is_err());
    }

    #[test]
    fn ast_policy_denies_metadata_schema_functions_without_allow_metadata() {
        let policy = CredentialPolicy::default();
        assert!(
            enforce_sql_policy(
                "select pg_catalog.obj_description(1259, 'pg_class')",
                &policy
            )
            .is_err()
        );
        assert!(
            enforce_sql_policy(
                "select information_schema._pg_char_max_length(1043, 10)",
                &policy,
            )
            .is_err()
        );
    }

    #[test]
    fn ast_policy_allows_metadata_schema_functions_when_allow_metadata_enabled() {
        let policy = CredentialPolicy {
            allow_metadata: true,
            ..CredentialPolicy::default()
        };
        assert!(
            enforce_sql_policy(
                "select pg_catalog.obj_description(1259, 'pg_class')",
                &policy
            )
            .is_ok()
        );
        assert!(
            enforce_sql_policy(
                "select information_schema._pg_char_max_length(1043, 10)",
                &policy,
            )
            .is_ok()
        );
    }

    #[test]
    fn ast_policy_denies_builtin_functions_after_metadata_is_allowed() {
        let policy = CredentialPolicy {
            allow_metadata: true,
            ..CredentialPolicy::default()
        };
        assert!(enforce_sql_policy("select pg_catalog.pg_sleep(1)", &policy).is_err());
    }

    #[test]
    fn ast_policy_matches_denied_functions_by_short_or_exact_full_name() {
        let policy = CredentialPolicy {
            allow_metadata: true,
            denied_functions: vec!["custom_blocked".to_owned()],
            ..CredentialPolicy::default()
        };
        assert!(enforce_sql_policy("select custom_blocked()", &policy).is_err());
        assert!(enforce_sql_policy("select public.custom_blocked()", &policy).is_err());

        let policy = CredentialPolicy {
            allow_metadata: true,
            denied_functions: vec!["public.custom_blocked".to_owned()],
            ..CredentialPolicy::default()
        };
        assert!(enforce_sql_policy("select public.custom_blocked()", &policy).is_err());
        assert!(enforce_sql_policy("select custom_blocked()", &policy).is_ok());
        assert!(enforce_sql_policy("select other.custom_blocked()", &policy).is_ok());
    }

    #[test]
    fn ast_policy_blocks_whitespace_and_quoting_evasions() {
        let policy = CredentialPolicy::default();
        assert!(enforce_sql_policy("select pg_sleep (10)", &policy).is_err());
        assert!(enforce_sql_policy("select * from pg_stat_activity", &policy).is_err());
        assert!(enforce_sql_policy("select * from information_schema.tables", &policy).is_err());
    }

    #[test]
    fn ast_policy_no_false_positive_on_pg_prefixed_alias() {
        let policy = CredentialPolicy::default();
        assert!(enforce_sql_policy("select count(*) as pg_total from payments", &policy).is_ok());
    }

    #[test]
    fn ast_policy_blocks_table_functions_in_from() {
        let policy = CredentialPolicy::default();
        assert!(
            enforce_sql_policy("select * from dblink('h','select 1') as t(a int)", &policy)
                .is_err()
        );
        let policy = CredentialPolicy {
            denied_functions: vec!["my_udf".to_owned()],
            ..CredentialPolicy::default()
        };
        assert!(enforce_sql_policy("select * from my_udf(1)", &policy).is_err());
    }

    #[test]
    fn ast_policy_blocks_data_modifying_cte() {
        let policy = CredentialPolicy::default();
        assert!(
            enforce_sql_policy(
                "with x as (insert into t values (1) returning id) select * from x",
                &policy,
            )
            .is_err()
        );
    }

    #[test]
    fn ast_policy_rejects_denied_sql_value_function() {
        let policy = CredentialPolicy {
            denied_functions: vec!["current_user".to_owned()],
            ..CredentialPolicy::default()
        };
        assert!(enforce_sql_policy("select current_user", &policy).is_err());
    }

    #[test]
    fn ast_policy_requires_explain_permission() {
        assert!(enforce_sql_policy("explain select 1", &CredentialPolicy::default()).is_err());
        let policy = CredentialPolicy {
            allow_explain: true,
            ..CredentialPolicy::default()
        };
        assert!(enforce_sql_policy("explain select 1", &policy).is_ok());
        assert!(enforce_sql_policy("explain analyze select 1", &policy).is_err());
    }
}

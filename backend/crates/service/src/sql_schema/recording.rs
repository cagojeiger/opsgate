use opsgate_db::AuditRepo;
use opsgate_model::Caller;
use opsgate_model::credential::Credential;
use serde_json::Value;

use crate::audit::runtime::{CredentialSnapshot, outcome, reason};

use super::input::NormalizedInput;
use super::output::SqlSchemaOutput;

pub(super) struct SchemaRecorder<'a> {
    audit: &'a AuditRepo,
    caller: &'a Caller,
    input: &'a NormalizedInput,
    credential: Option<CredentialSnapshot>,
}

impl<'a> SchemaRecorder<'a> {
    pub(super) fn new(
        audit: &'a AuditRepo,
        caller: &'a Caller,
        input: &'a NormalizedInput,
    ) -> Self {
        Self {
            audit,
            caller,
            input,
            credential: None,
        }
    }

    pub(super) fn set_credential(&mut self, credential: &Credential) {
        self.credential = Some(CredentialSnapshot::from(credential));
    }

    pub(super) async fn denied(&self, kind: &str, message: &str) {
        self.record(outcome::DENIED, Some(kind), Some(message), None)
            .await;
    }

    pub(super) async fn err(&self, kind: &str, message: &str) {
        self.record(outcome::ERROR, Some(kind), Some(message), None)
            .await;
    }

    pub(super) async fn ok(&self, output: &SqlSchemaOutput) {
        self.record(outcome::OK, None, None, Some(output)).await;
    }

    async fn record(
        &self,
        outcome: &str,
        error_kind: Option<&str>,
        _error_message: Option<&str>,
        output: Option<&SqlSchemaOutput>,
    ) {
        let credential = self.credential.as_ref();
        crate::audit::runtime::append_tool_event(crate::audit::runtime::ToolEventRecord {
            audit: self.audit,
            caller: self.caller,
            tool: "sql.schema",
            outcome,
            credential,
            fallback_alias: &self.input.alias,
            purpose: Some(self.input.purpose.clone()),
            detail: audit_detail(self.input, credential, outcome, error_kind, output),
            failure_event: "sql.schema.audit_failed",
        })
        .await;
    }
}

pub(super) async fn record_bad_input(audit: &AuditRepo, caller: &Caller, alias: &str) {
    crate::audit::append_event(
        audit,
        pre_input_denial_audit_event(caller, alias, reason::BAD_INPUT),
        "sql.schema.audit_failed",
    )
    .await;
}

fn audit_detail(
    input: &NormalizedInput,
    credential: Option<&CredentialSnapshot>,
    outcome: &str,
    error_kind: Option<&str>,
    output: Option<&SqlSchemaOutput>,
) -> Value {
    let mut detail = serde_json::Map::new();
    detail.insert("schema_version".to_owned(), serde_json::json!(1));
    detail.insert("mode".to_owned(), serde_json::json!(input.mode));
    detail.insert("namespace".to_owned(), serde_json::json!(input.namespace));
    detail.insert("table".to_owned(), serde_json::json!(input.table));
    detail.insert("limit".to_owned(), serde_json::json!(input.limit));
    detail.insert("max_bytes".to_owned(), serde_json::json!(input.max_bytes));
    detail.insert("timeout_ms".to_owned(), serde_json::json!(input.timeout_ms));
    detail.insert(
        "include_indexes".to_owned(),
        serde_json::json!(input.include_indexes),
    );
    detail.insert("purpose".to_owned(), serde_json::json!(input.purpose));
    if let Some(database) = &input.database {
        detail.insert("database".to_owned(), serde_json::json!(database));
    }
    crate::audit::runtime::insert_reason_detail(&mut detail, outcome, error_kind);
    if let Some(credential) = credential {
        crate::audit::runtime::insert_credential_detail(
            &mut detail,
            credential.category.as_str(),
            &credential.provider,
            &credential.env,
        );
    }
    if let Some(output) = output {
        detail.insert(
            "returned_bytes".to_owned(),
            serde_json::json!(output.returned_bytes),
        );
        detail.insert(
            "latency_ms".to_owned(),
            serde_json::json!(output.latency_ms),
        );
        detail.insert("truncated".to_owned(), serde_json::json!(output.truncated));
        if let Some(page) = &output.page {
            detail.insert("returned".to_owned(), serde_json::json!(page.returned));
            detail.insert("has_more".to_owned(), serde_json::json!(page.has_more));
        }
        if let Some(table) = &output.table {
            detail.insert(
                "column_count".to_owned(),
                serde_json::json!(table.columns.len()),
            );
            detail.insert(
                "index_count".to_owned(),
                serde_json::json!(table.indexes.len()),
            );
        }
    }
    Value::Object(detail)
}

fn pre_input_denial_audit_event(
    caller: &Caller,
    alias: &str,
    reason: &str,
) -> crate::audit::AuditEvent {
    crate::audit::runtime::pre_input_denial_event(caller, "sql.schema", alias, reason, None)
}

#[cfg(test)]
mod tests {
    use opsgate_core::Result;

    use super::super::input::{SqlSchemaInput, normalize_input};
    use super::*;

    fn base_input() -> SqlSchemaInput {
        SqlSchemaInput {
            alias: "analytics".to_owned(),
            purpose: "Inspect schema safely".to_owned(),
            database: None,
            mode: String::new(),
            namespace: String::new(),
            table: String::new(),
            limit: None,
            cursor: String::new(),
            max_bytes: None,
            timeout_ms: None,
            include_indexes: false,
        }
    }

    #[test]
    fn audit_detail_is_secret_free_and_uses_specific_reason_keys() -> Result<()> {
        let input = normalize_input(SqlSchemaInput {
            mode: "table".to_owned(),
            table: "audit_logs".to_owned(),
            ..base_input()
        })?;
        let detail = audit_detail(&input, None, "denied", Some(reason::POLICY_DENIED), None);
        let serialized = detail.to_string();
        assert!(serialized.contains("denial_reason"));
        assert!(!serialized.contains("error_message_safe"));
        assert!(!serialized.contains("bad"));
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("database_url"));
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("\"reason\""));
        Ok(())
    }
}

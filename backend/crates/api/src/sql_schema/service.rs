use std::time::Instant;

use opsgate_core::{Error, Result};
use opsgate_db::{AuditRepo, CredentialRepo};
use opsgate_domain::Caller;
use opsgate_domain::credential::{Credential, CredentialCategory};
use serde_json::Value;

use super::executor::execute_schema_query;
use super::input::{NormalizedInput, SqlSchemaInput, normalize_input};
use super::output::{SqlSchemaOutput, finalize_output};
use super::policy::validate_policy;
use crate::audit::runtime::reason;
use crate::credential::snapshot::CredentialSnapshot;

#[derive(Clone)]
pub(crate) struct SqlSchemaService {
    credentials: CredentialRepo,
    audit: AuditRepo,
    sealer: opsgate_core::crypto::Sealer,
    pools: crate::target::pg_pool::TargetPgPools,
}

impl SqlSchemaService {
    pub fn new(
        credentials: CredentialRepo,
        audit: AuditRepo,
        sealer: opsgate_core::crypto::Sealer,
        pools: crate::target::pg_pool::TargetPgPools,
    ) -> Self {
        Self {
            credentials,
            audit,
            sealer,
            pools,
        }
    }

    pub async fn execute(&self, caller: &Caller, input: SqlSchemaInput) -> Result<SqlSchemaOutput> {
        let raw_alias = crate::audit::safe::message(&input.alias);
        let input = match normalize_input(input) {
            Ok(input) => input,
            Err(error) => {
                self.record_bad_input(caller, &raw_alias, &error).await;
                return Err(error);
            }
        };
        let mut recorder = SchemaRecorder::new(&self.audit, caller, &input);

        let row = match self
            .credentials
            .find_credential_secret_by_alias(caller.user.id, &input.alias)
            .await?
        {
            Some(row) => row,
            None => {
                recorder
                    .denied(reason::CREDENTIAL_NOT_FOUND, "credential not found")
                    .await;
                return Err(Error::not_found("credential not found"));
            }
        };
        let material = row.into_credential()?;
        let credential = material.credential;
        recorder.set_credential(&credential);

        if credential.category != CredentialCategory::Sql || credential.provider != "postgres" {
            recorder
                .denied(
                    reason::WRONG_CREDENTIAL_PROVIDER,
                    "credential is not sql/postgres",
                )
                .await;
            return Err(Error::validation(reason::WRONG_CREDENTIAL_PROVIDER));
        }
        if let Err(error) = validate_policy(&credential.policy, &input) {
            recorder
                .denied(reason::POLICY_DENIED, &error.to_string())
                .await;
            return Err(error);
        }
        let secret_ciphertext = match material.secret_ciphertext {
            Some(secret_ciphertext) => secret_ciphertext,
            None => {
                recorder
                    .err(reason::SECRET_DESTROYED, "credential secret is destroyed")
                    .await;
                return Err(Error::validation("credential secret is destroyed"));
            }
        };
        let secret = match crate::sql_common::open_sql_secret(
            &self.sealer,
            &credential.alias,
            &secret_ciphertext,
        ) {
            Ok(secret) => secret,
            Err(error) => {
                recorder
                    .err(reason::SECRET_OPEN_FAILED, "credential secret open failed")
                    .await;
                return Err(error);
            }
        };
        let target = match crate::target::postgres::prepare_postgres_target(
            crate::sql_common::credential_database_url(&credential)?,
            credential.allow_private_network,
            credential.allow_insecure_transport,
        )
        .await
        {
            Ok(target) => target,
            Err(error) => {
                recorder
                    .err(reason::TARGET_PREPARE_FAILED, "target prepare failed")
                    .await;
                return Err(error);
            }
        };

        let started = Instant::now();
        let mut output = match execute_schema_query(
            &self.pools,
            credential.id,
            &target,
            &secret,
            &input,
        )
        .await
        {
            Ok(output) => output,
            Err(error) => {
                recorder
                    .err(reason::SCHEMA_LOOKUP_FAILED, "sql schema lookup failed")
                    .await;
                return Err(error);
            }
        };
        output.latency_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        if let Err(error) = finalize_output(&mut output, &input) {
            recorder
                .err(reason::OUTPUT_FINALIZE_FAILED, "output finalize failed")
                .await;
            return Err(error);
        }
        recorder.ok(&output).await;
        Ok(output)
    }

    async fn record_bad_input(&self, caller: &Caller, alias: &str, _error: &Error) {
        self.record_pre_input_denial(caller, alias, reason::BAD_INPUT)
            .await;
    }

    async fn record_pre_input_denial(&self, caller: &Caller, alias: &str, reason: &str) {
        crate::audit::append_event(
            &self.audit,
            pre_input_denial_audit_event(caller, alias, reason),
            "sql.schema.audit_failed",
        )
        .await;
    }
}

struct SchemaRecorder<'a> {
    audit: &'a AuditRepo,
    caller: &'a Caller,
    input: &'a NormalizedInput,
    credential: Option<CredentialSnapshot>,
}

impl<'a> SchemaRecorder<'a> {
    fn new(audit: &'a AuditRepo, caller: &'a Caller, input: &'a NormalizedInput) -> Self {
        Self {
            audit,
            caller,
            input,
            credential: None,
        }
    }

    fn set_credential(&mut self, credential: &Credential) {
        self.credential = Some(CredentialSnapshot::from(credential));
    }

    async fn denied(&self, kind: &str, message: &str) {
        self.record("denied", Some(kind), Some(message), None).await;
    }

    async fn err(&self, kind: &str, message: &str) {
        self.record("error", Some(kind), Some(message), None).await;
    }

    async fn ok(&self, output: &SqlSchemaOutput) {
        self.record("ok", None, None, Some(output)).await;
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

    use super::*;

    fn base_input() -> SqlSchemaInput {
        SqlSchemaInput {
            alias: "analytics".to_owned(),
            purpose: "Inspect schema safely".to_owned(),
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

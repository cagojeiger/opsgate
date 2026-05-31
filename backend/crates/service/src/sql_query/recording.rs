use opsgate_core::Error;
use opsgate_db::{AuditRepo, SqlQueryHistoryParams, SqlQueryHistoryRepo};
use opsgate_model::Caller;
use opsgate_model::credential::Credential;
use serde_json::Value;

use crate::audit::runtime::CredentialSnapshot;
use crate::audit::runtime::reason;

use super::input::NormalizedInput;
use super::output::SqlQueryOutput;

pub(super) struct QueryRecorder<'a> {
    history: &'a SqlQueryHistoryRepo,
    audit: &'a AuditRepo,
    caller: &'a Caller,
    input: &'a NormalizedInput,
    credential: Option<CredentialSnapshot>,
}

impl<'a> QueryRecorder<'a> {
    pub(super) fn new(
        history: &'a SqlQueryHistoryRepo,
        audit: &'a AuditRepo,
        caller: &'a Caller,
        input: &'a NormalizedInput,
    ) -> Self {
        Self {
            history,
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
        self.record("denied", Some(kind), Some(message), None).await;
    }

    pub(super) async fn err(&self, kind: &str, message: &str) {
        self.record("error", Some(kind), Some(message), None).await;
    }

    pub(super) async fn ok(&self, output: &SqlQueryOutput) {
        self.record("ok", None, None, Some(output)).await;
    }

    async fn record(
        &self,
        outcome: &str,
        error_kind: Option<&str>,
        error_message: Option<&str>,
        output: Option<&SqlQueryOutput>,
    ) {
        self.record_audit(outcome, error_kind, output).await;
        let credential = self.credential.as_ref();
        let params = SqlQueryHistoryParams {
            owner_user_id: credential
                .map(|credential| credential.owner_user_id)
                .or(Some(self.caller.user.id)),
            actor_user_id: Some(self.caller.user.id),
            channel: crate::audit::runtime::history_channel_str(self.caller.channel).to_owned(),
            request_id: self.caller.request_id.clone(),
            credential_id: credential.map(|credential| credential.id),
            credential_alias: credential
                .map(|credential| credential.alias.clone())
                .unwrap_or_else(|| self.input.alias.clone()),
            credential_category: credential
                .map(|credential| credential.category.as_str().to_owned())
                .unwrap_or_default(),
            credential_provider: credential
                .map(|credential| credential.provider.clone())
                .unwrap_or_default(),
            credential_env: credential
                .map(|credential| credential.env.clone())
                .unwrap_or_default(),
            query_sha256: self.input.query_sha256.clone(),
            params_count: i32::try_from(self.input.params.len()).unwrap_or(i32::MAX),
            max_rows: self.input.max_rows,
            max_bytes: i32::try_from(self.input.max_bytes).unwrap_or(i32::MAX),
            timeout_ms: i32::try_from(self.input.timeout_ms).unwrap_or(i32::MAX),
            purpose: Some(self.input.purpose.clone()),
            outcome: outcome.to_owned(),
            latency_ms: output.map(|output| output.latency_ms),
            row_count: output.map(|output| i32::try_from(output.row_count).unwrap_or(i32::MAX)),
            returned_bytes: output
                .map(|output| i32::try_from(output.returned_bytes).unwrap_or(i32::MAX)),
            truncated: output.is_some_and(|output| output.truncated),
            result_columns: output
                .map(result_column_names)
                .unwrap_or_else(|| serde_json::json!([])),
            error_kind: error_kind.map(str::to_owned),
            error_message_safe: error_message.map(crate::audit::safe_message),
        };
        if let Err(error) = self.history.insert(params).await {
            tracing::error!(event = "sql.query.history_failed", detail = %error);
        }
    }

    async fn record_audit(
        &self,
        outcome: &str,
        error_kind: Option<&str>,
        output: Option<&SqlQueryOutput>,
    ) {
        let credential = self.credential.as_ref();
        crate::audit::runtime::append_tool_event(crate::audit::runtime::ToolEventRecord {
            audit: self.audit,
            caller: self.caller,
            tool: "sql.query",
            outcome,
            credential,
            fallback_alias: &self.input.alias,
            purpose: Some(self.input.purpose.clone()),
            detail: audit_detail(self.input, credential, outcome, error_kind, output),
            failure_event: "sql.query.audit_failed",
        })
        .await;
    }
}

pub(super) async fn record_bad_input(
    history: &SqlQueryHistoryRepo,
    audit: &AuditRepo,
    caller: &Caller,
    alias: &str,
    error: &Error,
) {
    crate::audit::append_event(
        audit,
        pre_input_denial_audit_event(caller, alias, reason::BAD_INPUT),
        "sql.query.audit_failed",
    )
    .await;
    if let Err(error) = history
        .insert(pre_input_denial_history_params(
            caller,
            alias,
            reason::BAD_INPUT,
            error,
        ))
        .await
    {
        tracing::error!(event = "sql.query.history_failed", detail = %error);
    }
}

fn audit_detail(
    input: &NormalizedInput,
    credential: Option<&CredentialSnapshot>,
    outcome: &str,
    error_kind: Option<&str>,
    output: Option<&SqlQueryOutput>,
) -> Value {
    let mut detail = serde_json::Map::new();
    detail.insert("schema_version".to_owned(), serde_json::json!(1));
    detail.insert(
        "query_sha256".to_owned(),
        serde_json::json!(input.query_sha256),
    );
    detail.insert(
        "params_count".to_owned(),
        serde_json::json!(input.params.len()),
    );
    detail.insert("max_rows".to_owned(), serde_json::json!(input.max_rows));
    detail.insert("max_bytes".to_owned(), serde_json::json!(input.max_bytes));
    detail.insert("timeout_ms".to_owned(), serde_json::json!(input.timeout_ms));
    detail.insert("purpose".to_owned(), serde_json::json!(input.purpose));
    if let Some(credential) = credential {
        crate::audit::runtime::insert_credential_detail(
            &mut detail,
            credential.category.as_str(),
            &credential.provider,
            &credential.env,
        );
    }
    crate::audit::runtime::insert_reason_detail(&mut detail, outcome, error_kind);
    if let Some(output) = output {
        detail.insert(
            "latency_ms".to_owned(),
            serde_json::json!(output.latency_ms),
        );
        detail.insert("row_count".to_owned(), serde_json::json!(output.row_count));
        detail.insert(
            "returned_bytes".to_owned(),
            serde_json::json!(output.returned_bytes),
        );
        detail.insert("truncated".to_owned(), serde_json::json!(output.truncated));
        detail.insert("result_columns".to_owned(), result_column_names(output));
    }
    Value::Object(detail)
}

fn result_column_names(output: &SqlQueryOutput) -> Value {
    serde_json::json!(&output.column_names)
}

/// Audit row for a pre-normalization denial. Records only the channel, the
/// (pre-sanitized) alias, and denial reason — never the raw input.
fn pre_input_denial_audit_event(
    caller: &Caller,
    alias: &str,
    reason: &str,
) -> crate::audit::AuditEvent {
    crate::audit::runtime::pre_input_denial_event(caller, "sql.query", alias, reason, None)
}

/// History row for a pre-normalization denial. `error_message_safe` carries the
/// (value-free, CR/LF-stripped) validation reason; no normalized fields exist.
fn pre_input_denial_history_params(
    caller: &Caller,
    alias: &str,
    reason: &str,
    error: &Error,
) -> SqlQueryHistoryParams {
    SqlQueryHistoryParams {
        owner_user_id: Some(caller.user.id),
        actor_user_id: Some(caller.user.id),
        channel: crate::audit::runtime::history_channel_str(caller.channel).to_owned(),
        request_id: caller.request_id.clone(),
        credential_id: None,
        credential_alias: alias.to_owned(),
        credential_category: String::new(),
        credential_provider: String::new(),
        credential_env: String::new(),
        query_sha256: String::new(),
        params_count: 0,
        max_rows: 0,
        max_bytes: 0,
        timeout_ms: 0,
        purpose: None,
        outcome: "denied".to_owned(),
        latency_ms: None,
        row_count: None,
        returned_bytes: None,
        truncated: false,
        result_columns: serde_json::json!([]),
        error_kind: Some(reason.to_owned()),
        error_message_safe: Some(crate::audit::safe_message(&error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use opsgate_core::Result;
    use opsgate_model::credential::{
        Credential, CredentialCategory, CredentialPolicy, CredentialTarget,
    };
    use uuid::Uuid;

    use super::super::output::build_column_output;
    use super::*;

    fn input() -> NormalizedInput {
        NormalizedInput {
            alias: "analytics".to_owned(),
            purpose: "Count recent rows".to_owned(),
            query: "select secret_col from payments where token = $1".to_owned(),
            params: vec![serde_json::json!("secret-param")],
            jsonpath: Vec::new(),
            max_rows: 100,
            max_bytes: 64 * 1024,
            timeout_ms: 3000,
            query_sha256: "hash".to_owned(),
        }
    }

    fn sql_credential() -> Credential {
        let now = Utc::now();
        Credential {
            id: Uuid::nil(),
            owner_user_id: Uuid::nil(),
            category: CredentialCategory::Sql,
            provider: "postgres".to_owned(),
            alias: "analytics".to_owned(),
            target: CredentialTarget::Sql {
                database_url: "postgres://db.example.test/app?sslmode=require".to_owned(),
            },
            description: String::new(),
            env: "prod".to_owned(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            has_tls_ca: false,
            created_at: now,
            updated_at: now,
        }
    }

    fn test_caller() -> opsgate_model::Caller {
        let now = Utc::now();
        opsgate_model::Caller {
            user: opsgate_model::User {
                id: uuid::Uuid::nil(),
                sub: "sub".to_owned(),
                email: "user@example.test".to_owned(),
                display_name: "User".to_owned(),
                is_active: true,
                created_at: now,
                updated_at: now,
            },
            channel: opsgate_model::Channel::Mcp,
            request_id: None,
            remote_ip: None,
            user_agent: None,
        }
    }

    #[test]
    fn audit_detail_stores_hash_but_not_query_params_or_values() -> Result<()> {
        let input = input();
        let rows = vec![serde_json::json!({"secret_col":"secret-value"})];
        let output = build_column_output(rows, &input, false)?;
        let credential = CredentialSnapshot::from(&sql_credential());
        let detail = audit_detail(&input, Some(&credential), "ok", None, Some(&output));
        let serialized = detail.to_string();
        assert!(serialized.contains("query_sha256"));
        assert!(serialized.contains("result_columns"));
        assert!(detail.get("shape").is_none());
        assert!(!serialized.contains("select secret_col"));
        assert!(!serialized.contains("secret-param"));
        assert!(!serialized.contains("secret-value"));
        assert!(!serialized.contains("db.example.test"));
        Ok(())
    }

    #[test]
    fn bad_input_denial_is_recorded_safely() {
        let caller = test_caller();
        let error = Error::validation("query exceeds maximum length");

        let history = pre_input_denial_history_params(&caller, "prod", reason::BAD_INPUT, &error);
        assert_eq!(history.outcome, "denied");
        assert_eq!(history.error_kind.as_deref(), Some(reason::BAD_INPUT));
        assert!(history.purpose.is_none());
        assert_eq!(history.credential_alias, "prod");
        assert!(history.query_sha256.is_empty());
        assert_eq!(history.params_count, 0);

        let audit = pre_input_denial_audit_event(&caller, "prod", reason::BAD_INPUT).into_params();
        assert_eq!(audit.outcome, "denied");
        assert_eq!(audit.action, "mcp.sql.query");
        assert_eq!(
            audit.detail.get("denial_reason"),
            Some(&serde_json::json!(reason::BAD_INPUT))
        );
    }
}

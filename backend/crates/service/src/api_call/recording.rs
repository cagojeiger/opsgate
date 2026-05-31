use opsgate_core::Error;
use opsgate_db::{ApiCallHistoryParams, ApiCallHistoryRepo, AuditRepo};
use opsgate_model::Caller;
use opsgate_model::credential::Credential;
use serde_json::Value;

use crate::audit::runtime::reason;
use crate::credential::snapshot::CredentialSnapshot;

use super::input::NormalizedApiCallInput;
use super::output::ApiCallOutput;

pub(super) struct CallRecorder<'a> {
    history: &'a ApiCallHistoryRepo,
    audit: &'a AuditRepo,
    caller: &'a Caller,
    input: &'a NormalizedApiCallInput,
    credential: Option<CredentialSnapshot>,
}

impl<'a> CallRecorder<'a> {
    pub(super) fn new(
        history: &'a ApiCallHistoryRepo,
        audit: &'a AuditRepo,
        caller: &'a Caller,
        input: &'a NormalizedApiCallInput,
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

    pub(super) async fn ok(&self, output: &ApiCallOutput) {
        self.record("ok", None, None, Some(output)).await;
    }

    async fn record(
        &self,
        outcome: &str,
        error_kind: Option<&str>,
        error_message: Option<&str>,
        output: Option<&ApiCallOutput>,
    ) {
        self.record_audit(outcome, error_kind, output).await;
        let credential = self.credential.as_ref();
        let params = ApiCallHistoryParams {
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
            method: self.input.method.clone(),
            request_path: self.input.request_path.clone(),
            query_keys: serde_json::json!(self.input.query.keys().cloned().collect::<Vec<_>>()),
            request_header_keys: serde_json::json!(
                self.input.headers.keys().cloned().collect::<Vec<_>>()
            ),
            projection_keys: serde_json::json!(self.input.jsonpath),
            max_bytes: i32::try_from(self.input.max_bytes).unwrap_or(i32::MAX),
            purpose: Some(self.input.purpose.clone()),
            outcome: outcome.to_owned(),
            status_code: output.map(|output| output.status_code),
            latency_ms: output.map(|output| output.latency_ms),
            original_bytes: output
                .map(|output| i32::try_from(output.original_bytes).unwrap_or(i32::MAX)),
            returned_bytes: output
                .map(|output| i32::try_from(output.returned_bytes).unwrap_or(i32::MAX)),
            truncated: output.is_some_and(|output| output.truncated),
            error_kind: error_kind.map(str::to_owned),
            error_message_safe: error_message.map(crate::audit::safe::message),
        };
        if let Err(error) = self.history.insert(params).await {
            tracing::error!(event = "api.call.history_failed", detail = %error);
        }
    }

    async fn record_audit(
        &self,
        outcome: &str,
        error_kind: Option<&str>,
        output: Option<&ApiCallOutput>,
    ) {
        let credential = self.credential.as_ref();
        crate::audit::runtime::append_tool_event(crate::audit::runtime::ToolEventRecord {
            audit: self.audit,
            caller: self.caller,
            tool: "api.call",
            outcome,
            credential,
            fallback_alias: &self.input.alias,
            purpose: Some(self.input.purpose.clone()),
            detail: audit_detail(self.input, credential, outcome, error_kind, output),
            failure_event: "api.call.audit_failed",
        })
        .await;
    }
}

pub(super) async fn record_bad_input(
    history: &ApiCallHistoryRepo,
    audit: &AuditRepo,
    caller: &Caller,
    alias: &str,
    error: &Error,
) {
    crate::audit::append_event(
        audit,
        pre_input_denial_audit_event(caller, alias, reason::BAD_INPUT),
        "api.call.audit_failed",
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
        tracing::error!(event = "api.call.history_failed", detail = %error);
    }
}

fn audit_detail(
    input: &NormalizedApiCallInput,
    credential: Option<&CredentialSnapshot>,
    outcome: &str,
    error_kind: Option<&str>,
    output: Option<&ApiCallOutput>,
) -> Value {
    let mut detail = serde_json::Map::new();
    detail.insert("schema_version".to_owned(), serde_json::json!(1));
    detail.insert("method".to_owned(), serde_json::json!(input.method));
    detail.insert(
        "request_path".to_owned(),
        serde_json::json!(input.request_path),
    );
    detail.insert("purpose".to_owned(), serde_json::json!(input.purpose));
    let query_keys = input.query.keys().cloned().collect::<Vec<_>>();
    if !query_keys.is_empty() {
        detail.insert("query_keys".to_owned(), serde_json::json!(query_keys));
    }
    let header_keys = input.headers.keys().cloned().collect::<Vec<_>>();
    if !header_keys.is_empty() {
        detail.insert(
            "request_header_keys".to_owned(),
            serde_json::json!(header_keys),
        );
    }
    if !input.jsonpath.is_empty() {
        detail.insert("jsonpath".to_owned(), serde_json::json!(input.jsonpath));
    }
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
            "status_code".to_owned(),
            serde_json::json!(output.status_code),
        );
        detail.insert(
            "latency_ms".to_owned(),
            serde_json::json!(output.latency_ms),
        );
        detail.insert(
            "response_bytes".to_owned(),
            serde_json::json!(output.original_bytes),
        );
        detail.insert(
            "returned_bytes".to_owned(),
            serde_json::json!(output.returned_bytes),
        );
        if output.truncated {
            detail.insert("truncated".to_owned(), serde_json::json!(true));
        }
    }
    Value::Object(detail)
}

fn pre_input_denial_audit_event(
    caller: &Caller,
    alias: &str,
    reason: &str,
) -> crate::audit::AuditEvent {
    crate::audit::runtime::pre_input_denial_event(caller, "api.call", alias, reason, None)
}

fn pre_input_denial_history_params(
    caller: &Caller,
    alias: &str,
    reason: &str,
    error: &Error,
) -> ApiCallHistoryParams {
    ApiCallHistoryParams {
        owner_user_id: Some(caller.user.id),
        actor_user_id: Some(caller.user.id),
        channel: crate::audit::runtime::history_channel_str(caller.channel).to_owned(),
        request_id: caller.request_id.clone(),
        credential_id: None,
        credential_alias: alias.to_owned(),
        credential_category: String::new(),
        credential_provider: String::new(),
        credential_env: String::new(),
        method: String::new(),
        request_path: String::new(),
        query_keys: serde_json::json!([]),
        request_header_keys: serde_json::json!([]),
        projection_keys: serde_json::json!([]),
        max_bytes: 0,
        purpose: None,
        outcome: "denied".to_owned(),
        status_code: None,
        latency_ms: None,
        original_bytes: None,
        returned_bytes: None,
        truncated: false,
        error_kind: Some(reason.to_owned()),
        error_message_safe: Some(crate::audit::safe::message(&error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use opsgate_core::Result;
    use opsgate_model::credential::{
        Credential, CredentialCategory, CredentialPolicy, CredentialTarget,
    };
    use serde_json::Value;
    use uuid::Uuid;

    use super::super::input::{ApiCallInput, MAX_MAX_BYTES, normalize_input};
    use super::*;

    fn base_input() -> ApiCallInput {
        ApiCallInput {
            alias: "prod".to_owned(),
            purpose: "Check pod phases".to_owned(),
            method: "GET".to_owned(),
            request_path: "/api/v1/pods".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: None,
            content_type: String::new(),
            jsonpath: Vec::new(),
            max_bytes: Some(4096),
        }
    }

    fn http_credential(policy: CredentialPolicy) -> Credential {
        let now = Utc::now();
        Credential {
            id: Uuid::nil(),
            owner_user_id: Uuid::nil(),
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod".to_owned(),
            target: CredentialTarget::Http {
                origin: "https://api.example.test".to_owned(),
                base_path: "/".to_owned(),
            },
            description: String::new(),
            env: "prod".to_owned(),
            tags: Vec::new(),
            policy,
            allow_private_network: false,
            allow_insecure_transport: false,
            has_tls_ca: false,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn history_message_is_bounded_and_single_line() {
        let message = format!("secret\r\n{}", "x".repeat(600));
        let safe = crate::audit::safe::message(&message);
        assert!(!safe.contains(['\r', '\n']));
        assert_eq!(safe.chars().count(), 512);
    }

    #[test]
    fn audit_detail_stores_only_safe_request_facts() -> Result<()> {
        let input = normalize_input(ApiCallInput {
            method: "POST".to_owned(),
            query: BTreeMap::from([("token".to_owned(), "query-secret".to_owned())]),
            headers: BTreeMap::from([("Accept".to_owned(), "application/json".to_owned())]),
            body: Some(serde_json::json!({"secret": "body-secret"})),
            jsonpath: vec!["$.items[*].metadata.name".to_owned()],
            ..base_input()
        })?;
        let credential = CredentialSnapshot::from(&http_credential(CredentialPolicy::default()));
        let detail = audit_detail(
            &input,
            Some(&credential),
            "denied",
            Some(reason::POLICY_DENIED),
            None,
        );
        let serialized = detail.to_string();
        assert!(serialized.contains("query_keys"));
        assert!(serialized.contains("request_header_keys"));
        assert!(serialized.contains("denial_reason"));
        assert!(!serialized.contains("query-secret"));
        assert!(!serialized.contains("body-secret"));
        assert!(!serialized.contains("api.example.test"));
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("\"reason\""));
        Ok(())
    }

    #[test]
    fn audit_detail_uses_top_level_truncated_flag() -> Result<()> {
        let input = normalize_input(base_input())?;
        let output = ApiCallOutput {
            status_code: 200,
            headers: BTreeMap::new(),
            body: Value::Null,
            truncated: true,
            original_bytes: MAX_MAX_BYTES + 1,
            returned_bytes: 0,
            latency_ms: 12,
            more: None,
        };

        let detail = audit_detail(&input, None, "ok", None, Some(&output));
        assert_eq!(detail.get("truncated"), Some(&serde_json::json!(true)));
        Ok(())
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
    fn bad_input_denial_is_recorded_safely() {
        let caller = test_caller();
        let error = Error::validation("purpose must be at least 8 characters");

        let history = pre_input_denial_history_params(&caller, "prod", reason::BAD_INPUT, &error);
        assert_eq!(history.outcome, "denied");
        assert_eq!(history.error_kind.as_deref(), Some(reason::BAD_INPUT));
        assert!(history.purpose.is_none());
        assert_eq!(history.credential_alias, "prod");
        assert!(history.method.is_empty());
        assert_eq!(history.status_code, None);

        let audit = pre_input_denial_audit_event(&caller, "prod", reason::BAD_INPUT).into_params();
        assert_eq!(audit.outcome, "denied");
        assert_eq!(audit.action, "mcp.api.call");
        assert!(audit.purpose.is_none());
        assert_eq!(
            audit.detail.get("denial_reason"),
            Some(&serde_json::json!(reason::BAD_INPUT))
        );
    }
}

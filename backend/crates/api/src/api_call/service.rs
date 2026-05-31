use opsgate_core::{Error, Result};
use opsgate_db::{ApiCallHistoryParams, ApiCallHistoryRepo, AuditRepo, CredentialRepo};
use opsgate_domain::Caller;
use opsgate_domain::credential::{Credential, CredentialCategory};
use serde_json::Value;

use crate::audit::runtime::reason;
use crate::credential::secret;
use crate::credential::snapshot::CredentialSnapshot;
use crate::target::http::TargetHttpClients;
use std::time::Duration;

use super::input::{ApiCallInput, NormalizedApiCallInput, normalize_input};
use super::output::ApiCallOutput;
use super::policy::{validate_no_secret_header_override, validate_policy_boundary};
use super::target::execute_target_call;

const TARGET_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub(crate) struct ApiCallService {
    credentials: CredentialRepo,
    history: ApiCallHistoryRepo,
    audit: AuditRepo,
    sealer: opsgate_core::crypto::Sealer,
    target_clients: TargetHttpClients,
}

impl ApiCallService {
    pub fn new(
        credentials: CredentialRepo,
        history: ApiCallHistoryRepo,
        audit: AuditRepo,
        sealer: opsgate_core::crypto::Sealer,
    ) -> Result<Self> {
        Ok(Self {
            credentials,
            history,
            audit,
            sealer,
            target_clients: TargetHttpClients::new(TARGET_TIMEOUT)?,
        })
    }

    pub async fn call(&self, caller: &Caller, input: ApiCallInput) -> Result<ApiCallOutput> {
        // Sanitize the raw alias up front: on the bad-input path it is the only
        // request field we record, and it has not been validated yet.
        let raw_alias = crate::audit::safe::message(&input.alias);
        let input = match normalize_input(input) {
            Ok(input) => input,
            Err(error) => {
                self.record_bad_input(caller, &raw_alias, &error).await;
                return Err(error);
            }
        };
        let mut recorder = CallRecorder::new(&self.history, &self.audit, caller, &input);

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
        let secret_ciphertext = material.secret_ciphertext;
        let tls_ca = material.tls_ca;
        recorder.set_credential(&credential);

        if credential.category != CredentialCategory::Http {
            recorder
                .denied(
                    reason::WRONG_CREDENTIAL_CATEGORY,
                    "credential is not category=http",
                )
                .await;
            return Err(Error::validation(reason::WRONG_CREDENTIAL_CATEGORY));
        }
        if let Err(error) = validate_policy_boundary(&credential, &input) {
            recorder
                .denied(reason::POLICY_DENIED, &error.to_string())
                .await;
            return Err(error);
        }

        let secret_ciphertext = match secret_ciphertext {
            Some(secret_ciphertext) => secret_ciphertext,
            None => {
                recorder
                    .err(reason::SECRET_DESTROYED, "credential secret is destroyed")
                    .await;
                return Err(Error::validation("credential secret is destroyed"));
            }
        };
        let secret =
            match secret::open_http_headers(&self.sealer, &credential.alias, &secret_ciphertext) {
                Ok(secret) => secret,
                Err(error) => {
                    recorder
                        .err(reason::SECRET_OPEN_FAILED, "credential secret open failed")
                        .await;
                    return Err(error);
                }
            };
        if let Err(error) = validate_no_secret_header_override(&secret, &input) {
            recorder
                .denied(reason::POLICY_DENIED, &error.to_string())
                .await;
            return Err(error);
        }

        let output = match execute_target_call(
            &self.target_clients,
            &credential,
            tls_ca.as_deref(),
            &input,
            &secret,
        )
        .await
        {
            Ok(output) => output,
            Err(error) => {
                recorder.err(error.kind, error.message).await;
                return Err(error.error);
            }
        };
        recorder.ok(&output).await;
        Ok(output)
    }

    /// Record an input-validation rejection (before a normalized input exists).
    /// Mirrors the per-tool denial stream so input-shaped abuse is still audited.
    async fn record_bad_input(&self, caller: &Caller, alias: &str, error: &Error) {
        self.record_pre_input_denial(caller, alias, reason::BAD_INPUT, error)
            .await;
    }

    async fn record_pre_input_denial(
        &self,
        caller: &Caller,
        alias: &str,
        reason: &str,
        error: &Error,
    ) {
        crate::audit::append_event(
            &self.audit,
            pre_input_denial_audit_event(caller, alias, reason),
            "api.call.audit_failed",
        )
        .await;
        if let Err(error) = self
            .history
            .insert(pre_input_denial_history_params(
                caller, alias, reason, error,
            ))
            .await
        {
            tracing::error!(event = "api.call.history_failed", detail = %error);
        }
    }
}

struct CallRecorder<'a> {
    history: &'a ApiCallHistoryRepo,
    audit: &'a AuditRepo,
    caller: &'a Caller,
    input: &'a NormalizedApiCallInput,
    credential: Option<CredentialSnapshot>,
}

impl<'a> CallRecorder<'a> {
    fn new(
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

    fn set_credential(&mut self, credential: &Credential) {
        self.credential = Some(CredentialSnapshot::from(credential));
    }

    async fn denied(&self, kind: &str, message: &str) {
        self.record("denied", Some(kind), Some(message), None).await;
    }

    async fn err(&self, kind: &str, message: &str) {
        self.record("error", Some(kind), Some(message), None).await;
    }

    async fn ok(&self, output: &ApiCallOutput) {
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

/// Audit row for a pre-normalization denial. Records only the channel, the
/// (pre-sanitized) alias, and denial reason — never the raw input.
fn pre_input_denial_audit_event(
    caller: &Caller,
    alias: &str,
    reason: &str,
) -> crate::audit::AuditEvent {
    crate::audit::runtime::pre_input_denial_event(caller, "api.call", alias, reason, None)
}

/// History row for a pre-normalization denial. `error_message_safe` carries the
/// (value-free, CR/LF-stripped) validation reason; no normalized fields exist.
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

    use serde_json::Value;

    use super::super::input::MAX_MAX_BYTES;
    use super::*;
    use chrono::Utc;
    use opsgate_domain::credential::{CredentialPolicy, CredentialTarget};
    use uuid::Uuid;

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

    fn test_caller() -> opsgate_domain::Caller {
        let now = Utc::now();
        opsgate_domain::Caller {
            user: opsgate_domain::User {
                id: uuid::Uuid::nil(),
                sub: "sub".to_owned(),
                email: "user@example.test".to_owned(),
                display_name: "User".to_owned(),
                is_active: true,
                created_at: now,
                updated_at: now,
            },
            channel: opsgate_domain::Channel::Mcp,
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

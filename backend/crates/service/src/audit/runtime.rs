use opsgate_db::AuditRepo;
use opsgate_model::{Caller, Channel};
use serde_json::Value;

use crate::credential::snapshot::CredentialSnapshot;

use super::actor::caller_actor;
use super::event::channel_str;
use super::{AuditEvent, AuditOutcome, AuditTarget, append_event};

pub(crate) mod reason {
    pub const BAD_INPUT: &str = "bad_input";
    pub const CREDENTIAL_NOT_FOUND: &str = "credential_not_found";
    pub const POLICY_DENIED: &str = "policy_denied";
    pub const OUTPUT_BUILD_FAILED: &str = "output_build_failed";
    pub const OUTPUT_FINALIZE_FAILED: &str = "output_finalize_failed";
    pub const QUERY_FAILED: &str = "query_failed";
    pub const SCHEMA_LOOKUP_FAILED: &str = "schema_lookup_failed";
    pub const SECRET_DESTROYED: &str = "secret_destroyed";
    pub const SECRET_OPEN_FAILED: &str = "secret_open_failed";
    pub const TARGET_NOT_JSON: &str = "target_not_json";
    pub const TARGET_PREPARE_FAILED: &str = "target_prepare_failed";
    pub const TARGET_READ_FAILED: &str = "target_read_failed";
    pub const TARGET_REQUEST_FAILED: &str = "target_request_failed";
    pub const TARGET_URL_FAILED: &str = "target_url_failed";
    pub const WRONG_CREDENTIAL_CATEGORY: &str = "wrong_credential_category";
    pub const WRONG_CREDENTIAL_PROVIDER: &str = "wrong_credential_provider";
}

pub fn tool_event(
    caller: &Caller,
    tool: &'static str,
    outcome: &str,
    credential_id: Option<String>,
    credential_alias: String,
    purpose: Option<String>,
    detail: Value,
) -> AuditEvent {
    let channel = caller.channel;
    let mut event = AuditEvent::new(
        format!("{}.{}", channel_str(channel), tool),
        channel,
        AuditOutcome::from_str(outcome),
    )
    .actor(caller_actor(caller))
    .target(AuditTarget::credential(credential_id, credential_alias))
    .detail(detail);
    if let Some(purpose) = purpose {
        event = event.purpose(purpose);
    }
    event
}

pub struct ToolEventRecord<'a> {
    pub(crate) audit: &'a AuditRepo,
    pub(crate) caller: &'a Caller,
    pub(crate) tool: &'static str,
    pub(crate) outcome: &'a str,
    pub(crate) credential: Option<&'a CredentialSnapshot>,
    pub(crate) fallback_alias: &'a str,
    pub(crate) purpose: Option<String>,
    pub(crate) detail: Value,
    pub(crate) failure_event: &'static str,
}

pub async fn append_tool_event(record: ToolEventRecord<'_>) {
    let event = tool_event(
        record.caller,
        record.tool,
        record.outcome,
        record
            .credential
            .map(|credential| credential.id.to_string()),
        record
            .credential
            .map(|credential| credential.alias.clone())
            .unwrap_or_else(|| record.fallback_alias.to_owned()),
        record.purpose,
        record.detail,
    );
    append_event(record.audit, event, record.failure_event).await;
}

pub fn history_channel_str(channel: Channel) -> &'static str {
    match channel {
        Channel::Api => "api",
        Channel::Mcp | Channel::Browser => "mcp",
    }
}

pub fn insert_credential_detail(
    detail: &mut serde_json::Map<String, Value>,
    category: &str,
    provider: &str,
    env: &str,
) {
    detail.insert(
        "credential_category".to_owned(),
        serde_json::json!(category),
    );
    detail.insert(
        "credential_provider".to_owned(),
        serde_json::json!(provider),
    );
    detail.insert("credential_env".to_owned(), serde_json::json!(env));
}

pub fn insert_reason_detail(
    detail: &mut serde_json::Map<String, Value>,
    outcome: &str,
    error_kind: Option<&str>,
) {
    if let Some(error_kind) = error_kind {
        let key = if outcome == "denied" {
            "denial_reason"
        } else {
            "error_kind"
        };
        detail.insert(key.to_owned(), serde_json::json!(error_kind));
    }
}

pub fn pre_input_denial_event(
    caller: &Caller,
    tool: &'static str,
    alias: &str,
    reason: &str,
    extra_detail: Option<(&'static str, Value)>,
) -> AuditEvent {
    let mut detail = serde_json::Map::new();
    detail.insert("schema_version".to_owned(), serde_json::json!(1));
    detail.insert("denial_reason".to_owned(), serde_json::json!(reason));
    if let Some((key, value)) = extra_detail {
        detail.insert(key.to_owned(), value);
    }
    tool_event(
        caller,
        tool,
        "denied",
        None,
        alias.to_owned(),
        None,
        Value::Object(detail),
    )
}

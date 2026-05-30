use opsgate_domain::Caller;
use serde_json::Value;

use super::actor::caller_actor;
use super::event::channel_str;
use super::{AuditEvent, AuditOutcome, AuditTarget};

pub(crate) mod reason {
    pub(crate) const BAD_INPUT: &str = "bad_input";
    pub(crate) const CREDENTIAL_NOT_FOUND: &str = "credential_not_found";
    pub(crate) const POLICY_DENIED: &str = "policy_denied";
    pub(crate) const QUERY_FAILED: &str = "query_failed";
    pub(crate) const SCHEMA_LOOKUP_FAILED: &str = "schema_lookup_failed";
    pub(crate) const SECRET_DESTROYED: &str = "secret_destroyed";
    pub(crate) const SECRET_OPEN_FAILED: &str = "secret_open_failed";
    pub(crate) const TARGET_NOT_JSON: &str = "target_not_json";
    pub(crate) const TARGET_REQUEST_FAILED: &str = "target_request_failed";
    pub(crate) const WRONG_CREDENTIAL_CATEGORY: &str = "wrong_credential_category";
    pub(crate) const WRONG_CREDENTIAL_PROVIDER: &str = "wrong_credential_provider";
}

pub(crate) fn tool_event(
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

pub(crate) fn insert_credential_detail(
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

pub(crate) fn insert_reason_detail(
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

pub(crate) fn pre_input_denial_event(
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

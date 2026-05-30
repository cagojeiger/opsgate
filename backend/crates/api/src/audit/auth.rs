use opsgate_db::AuditRepo;
use opsgate_domain::{Caller, Channel, ResolveAttrs};

use crate::auth::bearer::AuthError;
use crate::request_context::RequestMetadata;

use super::actor::{metadata_actor, optional_caller_actor};
use super::{AuditEvent, AuditOutcome, AuditTarget, append_event};

pub(crate) async fn record_auth_denied(
    audit: &AuditRepo,
    channel: Channel,
    metadata: &RequestMetadata,
    error: &AuthError,
) {
    let Some(event) = auth_denied_event(channel, metadata, error) else {
        return;
    };
    append_event(audit, event, "auth.audit_failed").await;
}

pub(crate) fn auth_denied_event(
    channel: Channel,
    metadata: &RequestMetadata,
    error: &AuthError,
) -> Option<AuditEvent> {
    if matches!(error, AuthError::MissingToken) {
        return None;
    }
    let reason = auth_denial_reason(error);
    let detail = serde_json::json!({
        "schema_version": 1,
        "denial_reason": reason,
    });
    Some(
        AuditEvent::new(
            format!("{}.auth.denied", super::event::channel_str(channel)),
            channel,
            AuditOutcome::Denied,
        )
        .actor(metadata_actor(metadata))
        .target(AuditTarget::identity(None, None))
        .detail(detail),
    )
}

pub(crate) async fn record_signup(
    audit: &AuditRepo,
    caller: Option<&Caller>,
    outcome: AuditOutcome,
    denial_reason: Option<&str>,
    attrs: &ResolveAttrs,
    metadata: &RequestMetadata,
) {
    let event = signup_event(caller, outcome, denial_reason, attrs, metadata);
    append_event(audit, event, "browser.signup.audit_failed").await;
}

pub(crate) fn signup_event(
    caller: Option<&Caller>,
    outcome: AuditOutcome,
    denial_reason: Option<&str>,
    attrs: &ResolveAttrs,
    metadata: &RequestMetadata,
) -> AuditEvent {
    let mut detail = serde_json::Map::new();
    detail.insert("schema_version".to_owned(), serde_json::json!(1));
    detail.insert("sub".to_owned(), serde_json::json!(attrs.sub.clone()));
    detail.insert("email".to_owned(), serde_json::json!(attrs.email.clone()));
    if let Some(reason) = denial_reason {
        detail.insert("denial_reason".to_owned(), serde_json::json!(reason));
    }
    AuditEvent::new("browser.signup", Channel::Browser, outcome)
        .actor(optional_caller_actor(caller, metadata))
        .target(AuditTarget::identity(
            caller.map(|caller| caller.user.id.to_string()),
            Some(attrs.sub.clone()),
        ))
        .detail(serde_json::Value::Object(detail))
}

fn auth_denial_reason(error: &AuthError) -> &'static str {
    match error {
        AuthError::MissingToken => "missing_token",
        AuthError::InvalidToken => "invalid_token",
        AuthError::NotRegistered => "not_registered",
        AuthError::InsufficientRole => "insufficient_role",
        AuthError::Inactive => "inactive_user",
        AuthError::Internal => "internal_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_denied_event_carries_request_metadata_but_skips_missing_token()
    -> Result<(), Box<dyn std::error::Error>> {
        let metadata = RequestMetadata {
            request_id: Some("req-auth".to_owned()),
            remote_ip: Some("203.0.113.7".to_owned()),
            user_agent: Some("opsgate-test".to_owned()),
        };

        let params = auth_denied_event(Channel::Mcp, &metadata, &AuthError::NotRegistered)
            .ok_or("registered auth denial row missing")?
            .into_params();

        assert_eq!(params.action, "mcp.auth.denied");
        assert_eq!(params.channel, "mcp");
        assert_eq!(params.outcome, "denied");
        assert_eq!(params.request_id.as_deref(), Some("req-auth"));
        assert_eq!(params.actor_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(params.actor_user_agent.as_deref(), Some("opsgate-test"));
        assert_eq!(
            params.detail.get("denial_reason"),
            Some(&serde_json::json!("not_registered"))
        );
        assert!(auth_denied_event(Channel::Api, &metadata, &AuthError::MissingToken).is_none());
        Ok(())
    }
}

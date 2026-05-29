use opsgate_db::{AuditLogParams, AuditRepo};

use crate::auth::bearer::AuthError;
use crate::request_context::RequestMetadata;

pub(crate) async fn record_auth_denied(
    audit: &AuditRepo,
    channel: &'static str,
    metadata: &RequestMetadata,
    error: &AuthError,
) {
    let Some(params) = auth_denied_params(channel, metadata, error) else {
        return;
    };
    if let Err(error) = audit.append(params).await {
        tracing::error!(event = "auth.audit_failed", detail = %error);
    }
}

fn auth_denied_params(
    channel: &'static str,
    metadata: &RequestMetadata,
    error: &AuthError,
) -> Option<AuditLogParams> {
    if matches!(error, AuthError::MissingToken) {
        return None;
    }
    let reason = auth_denial_reason(error);
    let detail = serde_json::json!({
        "schema_version": 1,
        "denial_reason": reason,
    });
    Some(AuditLogParams {
        action: format!("{channel}.auth.denied"),
        channel: channel.to_owned(),
        outcome: "denied".to_owned(),
        severity: "warning".to_owned(),
        actor_user_id: None,
        actor_role: None,
        actor_ip: metadata.remote_ip.clone(),
        actor_user_agent: metadata.user_agent.clone(),
        target_type: Some("identity".to_owned()),
        target_id: None,
        target_key: None,
        request_id: metadata.request_id.clone(),
        purpose: None,
        detail,
    })
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
    fn auth_denied_params_carries_request_metadata_but_skips_missing_token()
    -> Result<(), Box<dyn std::error::Error>> {
        let metadata = RequestMetadata {
            request_id: Some("req-auth".to_owned()),
            remote_ip: Some("203.0.113.7".to_owned()),
            user_agent: Some("opsgate-test".to_owned()),
        };

        let params = auth_denied_params("mcp", &metadata, &AuthError::NotRegistered)
            .ok_or("registered auth denial row missing")?;

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
        assert!(auth_denied_params("api", &metadata, &AuthError::MissingToken).is_none());
        Ok(())
    }
}

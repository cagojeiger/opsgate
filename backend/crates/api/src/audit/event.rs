use opsgate_db::{AuditLogParams, AuditRepo};
use opsgate_domain::Channel;
use serde_json::Value;

use super::target::AuditTarget;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuditOutcome {
    Ok,
    Denied,
    Error,
}

impl AuditOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Error => "error",
        }
    }

    pub(crate) fn from_str(value: &str) -> Self {
        match value {
            "ok" => Self::Ok,
            "denied" => Self::Denied,
            _ => Self::Error,
        }
    }

    fn severity(self) -> &'static str {
        match self {
            Self::Ok => "info",
            Self::Denied | Self::Error => "warning",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AuditEvent {
    action: String,
    channel: Channel,
    outcome: AuditOutcome,
    actor_user_id: Option<uuid::Uuid>,
    actor_role: Option<String>,
    actor_ip: Option<String>,
    actor_user_agent: Option<String>,
    request_id: Option<String>,
    target: Option<AuditTarget>,
    purpose: Option<String>,
    detail: Value,
}

impl AuditEvent {
    pub(crate) fn new(action: impl Into<String>, channel: Channel, outcome: AuditOutcome) -> Self {
        Self {
            action: action.into(),
            channel,
            outcome,
            actor_user_id: None,
            actor_role: None,
            actor_ip: None,
            actor_user_agent: None,
            request_id: None,
            target: None,
            purpose: None,
            detail: serde_json::json!({ "schema_version": 1 }),
        }
    }

    pub(crate) fn actor(mut self, actor: AuditActor) -> Self {
        self.actor_user_id = actor.user_id;
        self.actor_role = actor.role;
        self.actor_ip = actor.ip;
        self.actor_user_agent = actor.user_agent;
        self.request_id = actor.request_id;
        self
    }

    pub(crate) fn target(mut self, target: AuditTarget) -> Self {
        self.target = Some(target);
        self
    }

    pub(crate) fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    pub(crate) fn detail(mut self, detail: Value) -> Self {
        self.detail = detail;
        self
    }

    pub(crate) fn into_params(self) -> AuditLogParams {
        let (target_type, target_id, target_key) = self
            .target
            .map(AuditTarget::into_parts)
            .unwrap_or((None, None, None));
        AuditLogParams {
            action: self.action,
            channel: channel_str(self.channel).to_owned(),
            outcome: self.outcome.as_str().to_owned(),
            severity: self.outcome.severity().to_owned(),
            actor_user_id: self.actor_user_id,
            actor_role: self.actor_role,
            actor_ip: self.actor_ip,
            actor_user_agent: self.actor_user_agent,
            target_type,
            target_id,
            target_key,
            request_id: self.request_id,
            purpose: self.purpose,
            detail: self.detail,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AuditActor {
    pub(crate) user_id: Option<uuid::Uuid>,
    pub(crate) role: Option<String>,
    pub(crate) ip: Option<String>,
    pub(crate) user_agent: Option<String>,
    pub(crate) request_id: Option<String>,
}

pub(crate) async fn append_event(
    audit: &AuditRepo,
    event: AuditEvent,
    failure_event: &'static str,
) {
    if let Err(error) = audit.append(event.into_params()).await {
        tracing::error!(event = failure_event, detail = %error);
    }
}

pub(crate) fn channel_str(channel: Channel) -> &'static str {
    match channel {
        Channel::Browser => "browser",
        Channel::Api => "api",
        Channel::Mcp => "mcp",
    }
}

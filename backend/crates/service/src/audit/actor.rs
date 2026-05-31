use opsgate_model::Caller;

use super::event::AuditActor;

pub fn caller_actor(caller: &Caller) -> AuditActor {
    AuditActor {
        user_id: Some(caller.user.id),
        ip: caller.remote_ip.clone(),
        user_agent: caller.user_agent.clone(),
        request_id: caller.request_id.clone(),
    }
}

pub fn credential_actor(
    caller: &Caller,
    action: opsgate_db::CredentialAuditAction,
    reason: Option<String>,
    changed_fields: Vec<String>,
    detail: serde_json::Value,
) -> opsgate_db::CredentialAuditParams {
    opsgate_db::CredentialAuditParams {
        actor_user_id: caller.user.id,
        actor_ip: caller.remote_ip.clone(),
        actor_user_agent: caller.user_agent.clone(),
        request_id: caller.request_id.clone(),
        channel: Some(super::event::channel_str(caller.channel).to_owned()),
        action,
        reason,
        changed_fields,
        detail,
    }
}

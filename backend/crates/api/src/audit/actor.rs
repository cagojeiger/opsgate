use opsgate_model::Caller;

use crate::request_context::RequestMetadata;

use super::event::AuditActor;

pub(crate) fn caller_actor(caller: &Caller) -> AuditActor {
    AuditActor {
        user_id: Some(caller.user.id),
        ip: caller.remote_ip.clone(),
        user_agent: caller.user_agent.clone(),
        request_id: caller.request_id.clone(),
    }
}

pub(crate) fn optional_caller_actor(
    caller: Option<&Caller>,
    metadata: &RequestMetadata,
) -> AuditActor {
    AuditActor {
        user_id: caller.map(|caller| caller.user.id),
        ip: caller
            .and_then(|caller| caller.remote_ip.clone())
            .or_else(|| metadata.remote_ip.clone()),
        user_agent: caller
            .and_then(|caller| caller.user_agent.clone())
            .or_else(|| metadata.user_agent.clone()),
        request_id: caller
            .and_then(|caller| caller.request_id.clone())
            .or_else(|| metadata.request_id.clone()),
    }
}

pub(crate) fn metadata_actor(metadata: &RequestMetadata) -> AuditActor {
    AuditActor {
        user_id: None,
        ip: metadata.remote_ip.clone(),
        user_agent: metadata.user_agent.clone(),
        request_id: metadata.request_id.clone(),
    }
}

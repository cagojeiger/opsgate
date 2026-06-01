mod actor;
mod event;
pub(crate) mod runtime;

pub(crate) use actor::credential_actor;
pub(crate) use event::{AuditEvent, AuditOutcome, AuditTarget, append_event};

pub(crate) fn safe_message(value: &str) -> String {
    value.replace(['\r', '\n'], " ").chars().take(512).collect()
}

use opsgate_db::{CredentialAuditAction, CredentialAuditParams};
use opsgate_domain::Caller;
use opsgate_domain::credential::RegisterCredentialInput;

pub(super) fn register_audit(
    caller: &Caller,
    input: &RegisterCredentialInput,
) -> CredentialAuditParams {
    crate::audit::credential_actor(
        caller,
        CredentialAuditAction::Register,
        None,
        Vec::new(),
        serde_json::json!({
            "provider": input.provider,
            "env": input.env,
            "tags": input.tags,
            "allow_private_network": input.allow_private_network,
            "allow_insecure_transport": input.allow_insecure_transport,
            "has_tls_ca": input.tls_server_ca.is_some(),
        }),
    )
}

pub(super) fn update_audit(
    caller: &Caller,
    reason: String,
    changed_fields: &[&'static str],
) -> CredentialAuditParams {
    let changed_fields = changed_fields
        .iter()
        .map(|field| (*field).to_owned())
        .collect::<Vec<_>>();
    crate::audit::credential_actor(
        caller,
        CredentialAuditAction::Update,
        Some(reason.trim().to_owned()),
        changed_fields.clone(),
        serde_json::json!({
            "changed_fields": changed_fields,
        }),
    )
}

pub(super) fn delete_audit(caller: &Caller, reason: String) -> CredentialAuditParams {
    crate::audit::credential_actor(
        caller,
        CredentialAuditAction::Delete,
        Some(reason.trim().to_owned()),
        Vec::new(),
        serde_json::json!({
            "secret_destroyed": true,
        }),
    )
}

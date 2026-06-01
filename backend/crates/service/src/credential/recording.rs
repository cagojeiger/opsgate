use opsgate_db::{CredentialAuditAction, CredentialAuditParams};
use opsgate_model::Caller;
use opsgate_model::credential::RegisterCredentialInput;

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

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use opsgate_db::CredentialAuditAction;
    use opsgate_model::credential::{CredentialPolicy, RegisterCredentialInput};
    use opsgate_model::{Caller, Channel, User};
    use uuid::Uuid;

    use super::super::input::{RegisterHttpCredentialInput, SecretHeaderInput};
    use super::*;

    fn caller() -> Caller {
        let now = Utc::now();
        Caller {
            user: User {
                id: Uuid::nil(),
                sub: "sub".to_owned(),
                email: "user@example.test".to_owned(),
                display_name: "User".to_owned(),
                is_active: true,
                created_at: now,
                updated_at: now,
            },
            channel: Channel::Mcp,
            request_id: Some("req-credential".to_owned()),
            remote_ip: Some("203.0.113.30".to_owned()),
            user_agent: Some("opsgate-test".to_owned()),
        }
    }

    fn http_input() -> RegisterCredentialInput {
        RegisterHttpCredentialInput {
            provider: "k8s".to_owned(),
            alias: "prod".to_owned(),
            origin: "https://service.example.test".to_owned(),
            base_path: String::new(),
            secret_headers: vec![SecretHeaderInput {
                name: "Authorization".to_owned(),
                value: "Bearer secret-token".to_owned(),
            }],
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            tls_server_ca: String::new(),
            client_cert_pem: String::new(),
            client_key_pem: String::new(),
        }
        .into_domain()
    }

    #[test]
    fn register_audit_detail_excludes_target_and_secret_material() {
        let input = http_input();
        let audit = register_audit(&caller(), &input);
        let detail = audit.detail.to_string();

        assert!(matches!(audit.action, CredentialAuditAction::Register));
        assert_eq!(audit.channel.as_deref(), Some("mcp"));
        assert_eq!(audit.request_id.as_deref(), Some("req-credential"));
        assert_eq!(audit.actor_ip.as_deref(), Some("203.0.113.30"));
        assert_eq!(audit.actor_user_agent.as_deref(), Some("opsgate-test"));
        assert!(detail.contains("k8s"));
        assert!(!detail.contains("service.example.test"));
        assert!(!detail.contains("secret-token"));
        assert!(!detail.contains("Authorization"));
    }

    #[test]
    fn update_and_delete_audit_store_reason_without_secret_material() {
        let caller = caller();
        let update = update_audit(
            &caller,
            "  Allow readonly metadata query  ".to_owned(),
            &["policy"],
        );
        let delete = delete_audit(&caller, "  Retire old credential  ".to_owned());

        assert!(matches!(update.action, CredentialAuditAction::Update));
        assert_eq!(
            update.reason.as_deref(),
            Some("Allow readonly metadata query")
        );
        assert_eq!(update.request_id.as_deref(), Some("req-credential"));
        assert!(update.changed_fields.iter().any(|field| field == "policy"));
        assert!(!update.detail.to_string().contains("secret-token"));
        assert!(matches!(delete.action, CredentialAuditAction::Delete));
        assert_eq!(delete.reason.as_deref(), Some("Retire old credential"));
        assert!(!delete.detail.to_string().contains("secret-token"));
    }
}

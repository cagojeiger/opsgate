use crate::crypto::Sealer;
use opsgate_core::validation::validate_reason;
use opsgate_core::{Error, Result};
use opsgate_model::credential::{
    Credential, CredentialCategory, CredentialPolicy, normalize_policy_for_category,
    normalize_tags, validate_allowed_headers_do_not_overlap_secret, validate_env,
    validate_policy_for_category, validate_tags,
};

use super::input::UpdateCredentialInput;
use super::secret;

#[derive(Debug, Clone)]
pub struct CredentialUpdate {
    pub credential: Credential,
    pub changed_fields: Vec<&'static str>,
}

#[derive(Debug, Clone)]
pub(super) struct UpdatePlan {
    pub(super) reason: String,
    pub(super) description: Option<String>,
    pub(super) env: Option<String>,
    pub(super) tags: Option<Vec<String>>,
    pub(super) policy: Option<CredentialPolicy>,
    pub(super) changed_fields: Vec<&'static str>,
}

pub(super) fn plan_update(
    before: &Credential,
    input: UpdateCredentialInput,
    category: CredentialCategory,
    sealer: &Sealer,
    secret_ciphertext: Option<&[u8]>,
) -> Result<UpdatePlan> {
    let reason = validate_reason(&input.reason)?;
    let description = trim_optional(input.description);
    let env = trim_optional(input.env);
    if let Some(env) = &env {
        validate_env(env)?;
    }
    let tags = input.tags.map(normalize_tags);
    if let Some(tags) = &tags {
        validate_tags(tags)?;
    }
    let policy = input
        .policy
        .map(|policy| normalize_policy_for_category(policy, category));
    if let Some(policy) = &policy {
        validate_policy_for_category(policy, category)?;
    }

    if category == CredentialCategory::Http
        && let Some(policy) = &policy
    {
        validate_http_policy_secret_overlap(sealer, &before.alias, secret_ciphertext, policy)?;
    }

    let next_description = description.unwrap_or_else(|| before.description.clone());
    let next_env = env.unwrap_or_else(|| before.env.clone());
    let next_tags = tags.unwrap_or_else(|| before.tags.clone());
    let next_policy = policy.unwrap_or_else(|| before.policy.clone());
    let changed_fields = changed_fields(
        before,
        &next_description,
        &next_env,
        &next_tags,
        &next_policy,
    );
    if changed_fields.is_empty() {
        return Err(Error::validation("no mutable fields changed"));
    }

    Ok(UpdatePlan {
        reason,
        description: changed_fields
            .contains(&"description")
            .then_some(next_description),
        env: changed_fields.contains(&"env").then_some(next_env),
        tags: changed_fields.contains(&"tags").then_some(next_tags),
        policy: changed_fields.contains(&"policy").then_some(next_policy),
        changed_fields,
    })
}

pub(super) fn ensure_update_category(
    credential: &Credential,
    expected: CredentialCategory,
) -> Result<()> {
    if credential.category == expected {
        Ok(())
    } else {
        Err(Error::validation(format!(
            "alias {:?} is category {:?}, not {:?}",
            credential.alias,
            credential.category.as_str(),
            expected.as_str(),
        )))
    }
}

pub(super) fn validate_http_policy_secret_overlap(
    sealer: &Sealer,
    alias: &str,
    secret_ciphertext: Option<&[u8]>,
    policy: &CredentialPolicy,
) -> Result<()> {
    let ciphertext =
        secret_ciphertext.ok_or_else(|| Error::internal("credential secret missing"))?;
    let names = secret::open_http_header_names(sealer, alias, ciphertext)?;
    validate_allowed_headers_do_not_overlap_secret(policy, &names)
}

pub(super) fn changed_fields(
    before: &Credential,
    description: &str,
    env: &str,
    tags: &[String],
    policy: &CredentialPolicy,
) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if before.description != description {
        fields.push("description");
    }
    if before.env != env {
        fields.push("env");
    }
    if before.tags != tags {
        fields.push("tags");
    }
    if before.policy != *policy {
        fields.push("policy");
    }
    fields
}

pub(super) fn trim_optional(value: Option<String>) -> Option<String> {
    value.map(|value| value.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use chrono::Utc;
    use opsgate_core::Result;
    use opsgate_model::credential::{
        CredentialSecret, CredentialTarget, SecretHeader, normalize_policy_for_category,
    };
    use secrecy::SecretString;
    use uuid::Uuid;

    use super::*;

    fn stored_credential(category: CredentialCategory) -> Credential {
        Credential {
            id: Uuid::nil(),
            owner_user_id: Uuid::nil(),
            category,
            provider: match category {
                CredentialCategory::Http => "k8s",
                CredentialCategory::Sql => "postgres",
            }
            .to_owned(),
            alias: "prod".to_owned(),
            target: match category {
                CredentialCategory::Http => CredentialTarget::Http {
                    origin: "https://service.example.test".to_owned(),
                    base_path: "/".to_owned(),
                },
                CredentialCategory::Sql => CredentialTarget::Sql {
                    database_url: "postgres://db.example.test/app?sslmode=require".to_owned(),
                },
            },
            description: "old description".to_owned(),
            env: "prod".to_owned(),
            tags: vec!["prod".to_owned()],
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            has_tls_ca: false,
            has_client_cert: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn update_category_mismatch_is_validation() {
        let credential = stored_credential(CredentialCategory::Sql);
        let err = ensure_update_category(&credential, CredentialCategory::Http)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();

        assert!(err.contains("category"));
        assert!(err.contains("sql"));
        assert!(err.contains("http"));
    }

    #[test]
    fn changed_fields_ignore_noop_values() {
        let before = stored_credential(CredentialCategory::Http);

        assert!(
            changed_fields(
                &before,
                &before.description,
                &before.env,
                &before.tags,
                &before.policy,
            )
            .is_empty()
        );

        let changed = changed_fields(
            &before,
            "new description",
            &before.env,
            &before.tags,
            &before.policy,
        );
        assert_eq!(changed, ["description"]);
    }

    #[test]
    fn plan_update_trims_reason_and_keeps_only_changed_values() -> Result<()> {
        let before = stored_credential(CredentialCategory::Http);
        let key = base64::engine::general_purpose::STANDARD.encode([17_u8; 32]);
        let sealer = Sealer::new(crate::crypto::Cipher::new(&key)?);

        let plan = plan_update(
            &before,
            UpdateCredentialInput {
                alias: before.alias.clone(),
                reason: "  Refresh description  ".to_owned(),
                description: Some(" new description ".to_owned()),
                env: None,
                tags: None,
                policy: None,
            },
            CredentialCategory::Http,
            &sealer,
            None,
        )?;

        assert_eq!(plan.reason, "Refresh description");
        assert_eq!(plan.description.as_deref(), Some("new description"));
        assert!(plan.env.is_none());
        assert!(plan.tags.is_none());
        assert!(plan.policy.is_none());
        assert_eq!(plan.changed_fields, ["description"]);
        Ok(())
    }

    #[test]
    fn plan_update_rejects_noop_values() -> Result<()> {
        let before = stored_credential(CredentialCategory::Http);
        let key = base64::engine::general_purpose::STANDARD.encode([19_u8; 32]);
        let sealer = Sealer::new(crate::crypto::Cipher::new(&key)?);

        let err = plan_update(
            &before,
            UpdateCredentialInput {
                alias: before.alias.clone(),
                reason: "Refresh metadata".to_owned(),
                description: Some(before.description.clone()),
                env: None,
                tags: None,
                policy: None,
            },
            CredentialCategory::Http,
            &sealer,
            None,
        )
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();

        assert!(err.contains("no mutable fields changed"));
        Ok(())
    }

    #[test]
    fn http_policy_update_rejects_secret_header_overlap() -> Result<()> {
        let key = base64::engine::general_purpose::STANDARD.encode([13_u8; 32]);
        let cipher = crate::crypto::Cipher::new(&key)?;
        let sealer = Sealer::new(cipher);
        let secret = CredentialSecret::Http {
            headers: vec![SecretHeader {
                name: "X-Api-Key".to_owned(),
                value: SecretString::from("secret-token".to_owned()),
            }],
        };
        let ciphertext = crate::credential::secret::seal(&sealer, "prod", &secret)?;
        let policy = normalize_policy_for_category(
            CredentialPolicy {
                allowed_request_headers: vec!["x-api-key".to_owned()],
                ..CredentialPolicy::default()
            },
            CredentialCategory::Http,
        );

        let err = validate_http_policy_secret_overlap(
            &sealer,
            "prod",
            Some(ciphertext.as_slice()),
            &policy,
        )
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();

        assert!(err.contains("secret header"));
        assert!(!err.contains("secret-token"));
        Ok(())
    }
}

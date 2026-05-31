use std::collections::BTreeSet;

use opsgate_model::CredentialCategory;
use opsgate_model::credential::{Credential, CredentialPolicy};
use schemars::JsonSchema;
use serde::Serialize;

use super::CredentialUpdate;

#[derive(Debug, Serialize, JsonSchema)]
pub struct CredentialListOutput {
    pub credentials: Vec<CredentialOutput>,
    pub page: PageOutput,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PageOutput {
    pub limit: i64,
    pub returned: usize,
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CredentialOutput {
    pub alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<CredentialCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<CredentialPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_private_network: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_insecure_transport: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct RegisterCredentialOutput {
    pub alias: String,
    pub category: CredentialCategory,
    pub provider: String,
    pub env: String,
    pub tags: Vec<String>,
    pub description: String,
    pub created: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct UpdateCredentialOutput {
    pub alias: String,
    pub category: CredentialCategory,
    pub provider: String,
    pub env: String,
    pub tags: Vec<String>,
    pub description: String,
    pub updated: bool,
    pub changed_fields: Vec<&'static str>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DeleteCredentialOutput {
    pub alias: String,
    pub deleted: bool,
}

impl CredentialOutput {
    pub fn from_with_fields(credential: Credential, fields: Option<&BTreeSet<String>>) -> Self {
        Self {
            alias: credential.alias,
            category: include_field(fields, "category").then_some(credential.category),
            provider: include_field(fields, "provider").then_some(credential.provider),
            description: include_field(fields, "description").then_some(credential.description),
            env: include_field(fields, "env").then_some(credential.env),
            tags: include_field(fields, "tags").then_some(credential.tags),
            policy: include_field(fields, "policy").then_some(credential.policy),
            allow_private_network: include_field(fields, "allow_private_network")
                .then_some(credential.allow_private_network),
            allow_insecure_transport: include_field(fields, "allow_insecure_transport")
                .then_some(credential.allow_insecure_transport),
        }
    }
}

impl RegisterCredentialOutput {
    pub fn created(credential: Credential) -> Self {
        Self {
            alias: credential.alias,
            category: credential.category,
            provider: credential.provider,
            env: credential.env,
            tags: credential.tags,
            description: credential.description,
            created: true,
        }
    }
}

impl UpdateCredentialOutput {
    pub fn from_update(update: CredentialUpdate) -> Self {
        Self {
            alias: update.credential.alias,
            category: update.credential.category,
            provider: update.credential.provider,
            env: update.credential.env,
            tags: update.credential.tags,
            description: update.credential.description,
            updated: true,
            changed_fields: update.changed_fields,
        }
    }
}

impl DeleteCredentialOutput {
    pub fn deleted(alias: String) -> Self {
        Self {
            alias,
            deleted: true,
        }
    }
}

pub fn normalize_fields(fields: Vec<String>) -> Option<BTreeSet<String>> {
    let fields = fields
        .into_iter()
        .map(|field| field.trim().to_owned())
        .filter(|field| !field.is_empty())
        .collect::<BTreeSet<_>>();
    (!fields.is_empty()).then_some(fields)
}

fn include_field(fields: Option<&BTreeSet<String>>, field: &str) -> bool {
    fields.is_none_or(|fields| fields.contains(field))
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;

    fn credential() -> Credential {
        Credential {
            id: Uuid::nil(),
            owner_user_id: Uuid::nil(),
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod-api".to_owned(),
            target: opsgate_model::credential::CredentialTarget::Http {
                origin: "https://internal.example.test".to_owned(),
                base_path: "/secret-path".to_owned(),
            },
            description: "cluster api".to_owned(),
            env: "prod".to_owned(),
            tags: vec!["prod".to_owned(), "k8s".to_owned()],
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            has_tls_ca: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn output_excludes_target_and_secret_material() -> Result<(), serde_json::Error> {
        let output = CredentialOutput::from_with_fields(credential(), None);
        let json = serde_json::to_string(&output)?;

        assert!(json.contains("prod-api"));
        assert!(!json.contains("internal.example.test"));
        assert!(!json.contains("secret"));
        Ok(())
    }

    #[test]
    fn output_field_projection_keeps_alias() -> Result<(), serde_json::Error> {
        let fields = BTreeSet::from(["provider".to_owned()]);
        let output = CredentialOutput::from_with_fields(credential(), Some(&fields));
        let json = serde_json::to_string(&output)?;

        assert!(json.contains("prod-api"));
        assert!(json.contains("k8s"));
        assert!(output.category.is_none());
        assert!(output.policy.is_none());
        Ok(())
    }

    #[test]
    fn empty_field_projection_is_default_projection() {
        assert!(normalize_fields(Vec::new()).is_none());
        assert!(normalize_fields(vec![" ".to_owned()]).is_none());
    }
}

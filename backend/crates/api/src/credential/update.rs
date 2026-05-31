use opsgate_core::crypto::Sealer;
use opsgate_core::{Error, Result};
use opsgate_domain::credential::{
    Credential, CredentialCategory, CredentialPolicy,
    validate_allowed_headers_do_not_overlap_secret,
};

use super::secret;

#[derive(Debug, Clone)]
pub(crate) struct CredentialUpdate {
    pub credential: Credential,
    pub changed_fields: Vec<&'static str>,
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

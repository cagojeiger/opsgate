use opsgate_domain::credential::{Credential, CredentialCategory};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub(crate) struct CredentialSnapshot {
    pub(crate) id: Uuid,
    pub(crate) owner_user_id: Uuid,
    pub(crate) alias: String,
    pub(crate) category: CredentialCategory,
    pub(crate) provider: String,
    pub(crate) env: String,
}

impl From<&Credential> for CredentialSnapshot {
    fn from(credential: &Credential) -> Self {
        Self {
            id: credential.id,
            owner_user_id: credential.owner_user_id,
            alias: credential.alias.clone(),
            category: credential.category,
            provider: credential.provider.clone(),
            env: credential.env.clone(),
        }
    }
}

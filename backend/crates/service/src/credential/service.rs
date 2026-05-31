use crate::crypto::Sealer;
use opsgate_core::validation::validate_reason;
use opsgate_core::{Error, Result};
use opsgate_db::CredentialRepo;
use opsgate_model::Caller;
use opsgate_model::credential::{
    Credential, CredentialCategory, CredentialListParams, InsertCredentialParams,
    RegisterCredentialInput, UpdateCredentialParams, normalize_policy_for_category,
    normalize_register_input, normalize_tags as normalize_credential_tags,
    validate_alias as validate_credential_alias, validate_env as validate_credential_env,
    validate_policy_for_category, validate_register_input,
};
use uuid::Uuid;

use super::input::{
    DeleteCredentialInput, ListCredentialsInput, RegisterHttpCredentialInput,
    RegisterSqlCredentialInput, UpdateCredentialInput,
};
use super::listing::{
    CredentialListPage, CredentialSummary, normalize_list_input, validate_list_input,
};
use super::recording::{delete_audit, register_audit, update_audit};
use super::secret;
use super::target::{EndpointResolver, validate_register_target_ips};
use super::update::{
    CredentialUpdate, changed_fields, ensure_update_category, trim_optional,
    validate_http_policy_secret_overlap,
};

const DEFAULT_LIST_LIMIT: i64 = 50;
const MAX_LIST_LIMIT: i64 = 100;

#[derive(Clone)]
pub struct CredentialService {
    repo: CredentialRepo,
    sealer: Sealer,
    resolver: EndpointResolver,
}

impl CredentialService {
    pub fn new(repo: CredentialRepo, sealer: Sealer) -> Self {
        Self {
            repo,
            sealer,
            resolver: EndpointResolver::System,
        }
    }

    pub async fn register_http(
        &self,
        caller: &Caller,
        input: RegisterHttpCredentialInput,
    ) -> Result<Credential> {
        self.register(caller, input.into_domain()).await
    }

    pub async fn register_sql(
        &self,
        caller: &Caller,
        input: RegisterSqlCredentialInput,
    ) -> Result<Credential> {
        self.register(caller, input.into_domain()).await
    }

    async fn register(
        &self,
        caller: &Caller,
        input: RegisterCredentialInput,
    ) -> Result<Credential> {
        let owner_user_id = caller.user.id;
        let input = normalize_register_input(input);
        validate_register_input(&input)?;
        validate_register_target_ips(&self.resolver, &input).await?;
        let secret_ciphertext = secret::seal(&self.sealer, &input.alias, &input.secret)?;
        let tls_ca = input
            .tls_server_ca
            .as_ref()
            .map(|ca| ca.as_bytes().to_vec());
        let audit = register_audit(caller, &input);
        self.repo
            .insert_credential(
                InsertCredentialParams {
                    owner_user_id,
                    actor_user_id: owner_user_id,
                    category: input.category,
                    provider: input.provider,
                    alias: input.alias,
                    target: input.target,
                    secret_ciphertext,
                    description: input.description,
                    env: input.env,
                    tags: input.tags,
                    policy: input.policy,
                    allow_private_network: input.allow_private_network,
                    allow_insecure_transport: input.allow_insecure_transport,
                    tls_ca,
                },
                audit,
            )
            .await
    }

    pub async fn list(
        &self,
        owner_user_id: Uuid,
        input: ListCredentialsInput,
    ) -> Result<CredentialListPage> {
        let input = normalize_list_input(input);
        validate_list_input(&input, MAX_LIST_LIMIT)?;
        let limit = input.limit.unwrap_or(DEFAULT_LIST_LIMIT);
        let rows = self
            .repo
            .list_credentials(CredentialListParams {
                owner_user_id,
                category: input.category,
                provider: input.provider,
                env: input.env,
                tag: input.tag,
                q: input.q,
                cursor: input.cursor,
                limit: limit + 1,
            })
            .await?;
        let mut credentials = rows;
        let has_more = credentials.len() > usize::try_from(limit).unwrap_or(100);
        if has_more {
            credentials.truncate(usize::try_from(limit).unwrap_or(100));
        }
        let next_cursor = if has_more {
            credentials
                .last()
                .map(|credential| credential.alias.clone())
        } else {
            None
        };
        Ok(CredentialListPage {
            credentials,
            limit,
            has_more,
            next_cursor,
        })
    }

    pub async fn summary(&self, owner_user_id: Uuid) -> Result<CredentialSummary> {
        self.repo
            .credential_summary(owner_user_id)
            .await
            .map(CredentialSummary::from)
    }

    pub async fn update_http(
        &self,
        caller: &Caller,
        input: UpdateCredentialInput,
    ) -> Result<CredentialUpdate> {
        self.update(caller, input, CredentialCategory::Http).await
    }

    pub async fn update_sql(
        &self,
        caller: &Caller,
        input: UpdateCredentialInput,
    ) -> Result<CredentialUpdate> {
        self.update(caller, input, CredentialCategory::Sql).await
    }

    pub async fn delete(
        &self,
        caller: &Caller,
        input: DeleteCredentialInput,
    ) -> Result<Credential> {
        let owner_user_id = caller.user.id;
        let alias = input.alias.trim().to_owned();
        let reason = validate_reason(&input.reason)?;
        validate_credential_alias(&alias)?;
        self.repo
            .soft_delete_credential(
                owner_user_id,
                &alias,
                owner_user_id,
                delete_audit(caller, reason),
            )
            .await
    }

    async fn update(
        &self,
        caller: &Caller,
        input: UpdateCredentialInput,
        category: CredentialCategory,
    ) -> Result<CredentialUpdate> {
        let owner_user_id = caller.user.id;
        let alias = input.alias.trim().to_owned();
        let reason = validate_reason(&input.reason)?;
        validate_credential_alias(&alias)?;

        let material = self
            .repo
            .find_credential_secret_by_alias(owner_user_id, &alias)
            .await?
            .ok_or_else(|| Error::not_found("credential not found"))?
            .into_credential()?;
        let before = material.credential;
        ensure_update_category(&before, category)?;

        let description = trim_optional(input.description);
        let env = trim_optional(input.env);
        if let Some(env) = &env {
            validate_credential_env(env)?;
        }
        let tags = input.tags.map(normalize_credential_tags);
        if let Some(tags) = &tags {
            opsgate_model::credential::validate_tags(tags)?;
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
            validate_http_policy_secret_overlap(
                &self.sealer,
                &alias,
                material.secret_ciphertext.as_deref(),
                policy,
            )?;
        }

        let next_description = description
            .clone()
            .unwrap_or_else(|| before.description.clone());
        let next_env = env.clone().unwrap_or_else(|| before.env.clone());
        let next_tags = tags.clone().unwrap_or_else(|| before.tags.clone());
        let next_policy = policy.clone().unwrap_or_else(|| before.policy.clone());
        let changed_fields = changed_fields(
            &before,
            &next_description,
            &next_env,
            &next_tags,
            &next_policy,
        );
        if changed_fields.is_empty() {
            return Err(Error::validation("no mutable fields changed"));
        }

        let audit = update_audit(caller, reason, &changed_fields);
        let description = changed_fields
            .contains(&"description")
            .then_some(next_description);
        let env = changed_fields.contains(&"env").then_some(next_env);
        let tags = changed_fields.contains(&"tags").then_some(next_tags);
        let policy = changed_fields.contains(&"policy").then_some(next_policy);
        let credential = self
            .repo
            .update_credential_mutable_fields(
                UpdateCredentialParams {
                    owner_user_id,
                    actor_user_id: owner_user_id,
                    alias,
                    category,
                    description,
                    env,
                    tags,
                    policy,
                },
                audit,
            )
            .await?;
        Ok(CredentialUpdate {
            credential,
            changed_fields,
        })
    }
}

use opsgate_core::crypto::Sealer;
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

#[cfg(test)]
use super::input::SecretHeaderInput;
#[cfg(test)]
use opsgate_db::CredentialAuditAction;
#[cfg(test)]
use opsgate_model::credential::{
    CredentialPolicy, CredentialSecret, CredentialTarget, SecretHeader,
};
#[cfg(test)]
use secrecy::SecretString;

const DEFAULT_LIST_LIMIT: i64 = 50;
const MAX_LIST_LIMIT: i64 = 100;

#[derive(Clone)]
pub(crate) struct CredentialService {
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

    #[cfg(test)]
    fn with_resolver(repo: CredentialRepo, sealer: Sealer, resolver: EndpointResolver) -> Self {
        Self {
            repo,
            sealer,
            resolver,
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use base64::Engine;
    use chrono::Utc;
    use opsgate_model::{Channel, User};
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    fn service_with_ips(ips: Vec<IpAddr>) -> Result<CredentialService> {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://opsgate:opsgate@localhost/opsgate")
            .map_err(Error::internal)?;
        let key = base64::engine::general_purpose::STANDARD.encode([11_u8; 32]);
        let cipher = opsgate_core::crypto::Cipher::new(&key)?;
        Ok(CredentialService::with_resolver(
            CredentialRepo::new(pool),
            Sealer::new(cipher),
            EndpointResolver::Fixed(ips),
        ))
    }

    fn http_input(allow_private_network: bool) -> RegisterCredentialInput {
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
            allow_private_network,
            allow_insecure_transport: false,
            tls_server_ca: String::new(),
        }
        .into_domain()
    }

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
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

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

    #[tokio::test]
    async fn service_rejects_private_register_target_ip() -> Result<()> {
        let service = service_with_ips(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))])?;
        let err = validate_register_target_ips(&service.resolver, &http_input(false))
            .await
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(err.contains("private/link-local/loopback"));
        assert!(!err.contains("secret-token"));
        Ok(())
    }

    #[tokio::test]
    async fn service_rejects_ipv4_mapped_private_register_target_ip() -> Result<()> {
        let service = service_with_ips(vec![IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001,
        ))])?;
        let err = validate_register_target_ips(&service.resolver, &http_input(false))
            .await
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(err.contains("private/link-local/loopback"));
        assert!(!err.contains("::ffff"));
        Ok(())
    }

    #[tokio::test]
    async fn service_allows_private_register_target_when_explicitly_enabled() -> Result<()> {
        let service = service_with_ips(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))])?;
        assert!(
            validate_register_target_ips(&service.resolver, &http_input(true))
                .await
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn register_audit_detail_excludes_target_and_secret_material() {
        let input = http_input(false);
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
    fn http_policy_update_rejects_secret_header_overlap() -> Result<()> {
        let key = base64::engine::general_purpose::STANDARD.encode([13_u8; 32]);
        let cipher = opsgate_core::crypto::Cipher::new(&key)?;
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

    #[test]
    fn list_input_validation_matches_go_boundaries() {
        let valid = normalize_list_input(ListCredentialsInput {
            category: Some(CredentialCategory::Http),
            provider: Some(" k8s ".to_owned()),
            env: Some("prod".to_owned()),
            tag: Some(" Cluster ".to_owned()),
            q: Some(" osaka ".to_owned()),
            fields: Some(vec![" provider ".to_owned(), "env".to_owned()]),
            limit: Some(50),
            cursor: Some("prod-api".to_owned()),
        });
        assert!(validate_list_input(&valid, MAX_LIST_LIMIT).is_ok());
        assert_eq!(valid.tag.as_deref(), Some("cluster"));

        for input in [
            ListCredentialsInput {
                provider: Some("Bad".to_owned()),
                ..valid.clone()
            },
            ListCredentialsInput {
                env: Some("qa".to_owned()),
                ..valid.clone()
            },
            ListCredentialsInput {
                tag: Some("bad space".to_owned()),
                ..valid.clone()
            },
            ListCredentialsInput {
                q: Some("bad\nquery".to_owned()),
                ..valid.clone()
            },
            ListCredentialsInput {
                fields: Some((0..9).map(|idx| format!("field{idx}")).collect()),
                ..valid.clone()
            },
            ListCredentialsInput {
                fields: Some(vec!["origin".to_owned()]),
                ..valid.clone()
            },
            ListCredentialsInput {
                limit: Some(101),
                ..valid.clone()
            },
            ListCredentialsInput {
                cursor: Some("bad cursor".to_owned()),
                ..valid
            },
        ] {
            assert!(validate_list_input(&normalize_list_input(input), MAX_LIST_LIMIT).is_err());
        }
    }
}

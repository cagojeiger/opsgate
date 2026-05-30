use std::collections::BTreeMap;
use std::net::IpAddr;

use opsgate_core::crypto::Sealer;
use opsgate_core::validation::validate_reason;
use opsgate_core::{Error, Result};
use opsgate_db::{CredentialAuditAction, CredentialRepo, CredentialSummaryRows};
use opsgate_domain::Caller;
use opsgate_domain::credential::{
    Credential, CredentialCategory, CredentialListParams, CredentialPolicy, CredentialSecret,
    InsertCredentialParams, RegisterCredentialInput, SecretHeader, UpdateCredentialParams,
    normalize_policy_for_category, normalize_register_input,
    normalize_tags as normalize_credential_tags, validate_alias as validate_credential_alias,
    validate_allowed_headers_do_not_overlap_secret, validate_env as validate_credential_env,
    validate_policy_for_category, validate_provider as validate_credential_provider,
    validate_register_input, validate_tag as validate_credential_tag,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use uuid::Uuid;

use crate::target::ssrf::{BLOCKED_TARGET_IP_MESSAGE, target_ip_is_blocked};

const SECRET_DOMAIN: &str = "credentials";
const DEFAULT_LIST_LIMIT: i64 = 50;
const MAX_LIST_LIMIT: i64 = 100;
const MAX_LIST_Q: usize = 128;
const MAX_LIST_FIELDS: usize = 8;

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
        let owner_user_id = caller.user.id;
        let input = normalize_register_input(input.into_domain());
        validate_register_input(&input)?;
        self.validate_register_endpoint_ips(&input).await?;
        let secret_plaintext = secret_json(&input.secret)?;
        let secret_ciphertext = self
            .sealer
            .seal(SECRET_DOMAIN, &input.alias, &secret_plaintext)?;
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
                    endpoint: input.endpoint,
                    secret_ciphertext,
                    description: input.description,
                    env: input.env,
                    tags: input.tags,
                    policy: input.policy,
                    allow_private_network: input.allow_private_network,
                    tls_ca,
                },
                audit,
            )
            .await
    }

    pub async fn register_sql(
        &self,
        caller: &Caller,
        input: RegisterSqlCredentialInput,
    ) -> Result<Credential> {
        let owner_user_id = caller.user.id;
        let input = normalize_register_input(input.into_domain());
        validate_register_input(&input)?;
        self.validate_register_endpoint_ips(&input).await?;
        let secret_plaintext = secret_json(&input.secret)?;
        let secret_ciphertext = self
            .sealer
            .seal(SECRET_DOMAIN, &input.alias, &secret_plaintext)?;
        let audit = register_audit(caller, &input);
        self.repo
            .insert_credential(
                InsertCredentialParams {
                    owner_user_id,
                    actor_user_id: owner_user_id,
                    category: input.category,
                    provider: input.provider,
                    alias: input.alias,
                    endpoint: input.endpoint,
                    secret_ciphertext,
                    description: input.description,
                    env: input.env,
                    tags: input.tags,
                    policy: input.policy,
                    allow_private_network: input.allow_private_network,
                    tls_ca: None,
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
        validate_list_input(&input)?;
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
            opsgate_domain::credential::validate_tags(tags)?;
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

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct ListCredentialsInput {
    pub category: Option<CredentialCategory>,
    pub provider: Option<String>,
    pub env: Option<String>,
    pub tag: Option<String>,
    pub q: Option<String>,
    pub fields: Option<Vec<String>>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CredentialListPage {
    pub credentials: Vec<Credential>,
    pub limit: i64,
    pub has_more: bool,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct CredentialSummary {
    pub total: i64,
    pub by_category: BTreeMap<String, i64>,
    pub by_provider: BTreeMap<String, i64>,
    pub tags: BTreeMap<String, i64>,
}

impl From<CredentialSummaryRows> for CredentialSummary {
    fn from(rows: CredentialSummaryRows) -> Self {
        Self {
            total: rows.total,
            by_category: count_map(rows.by_category),
            by_provider: count_map(rows.by_provider),
            tags: count_map(rows.tags),
        }
    }
}

fn count_map(rows: Vec<opsgate_db::credential_repo::CountRow>) -> BTreeMap<String, i64> {
    rows.into_iter().map(|row| (row.key, row.count)).collect()
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct RegisterHttpCredentialInput {
    pub provider: String,
    pub alias: String,
    pub endpoint: String,
    pub secret_headers: Vec<SecretHeaderInput>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub env: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub policy: CredentialPolicy,
    #[serde(default)]
    pub allow_private_network: bool,
    #[serde(default)]
    pub tls_server_ca: String,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct RegisterSqlCredentialInput {
    #[serde(default)]
    pub provider: String,
    pub alias: String,
    pub endpoint: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub env: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub policy: CredentialPolicy,
    #[serde(default)]
    pub allow_private_network: bool,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct UpdateCredentialInput {
    pub alias: String,
    pub reason: String,
    pub description: Option<String>,
    pub env: Option<String>,
    pub tags: Option<Vec<String>>,
    pub policy: Option<CredentialPolicy>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct DeleteCredentialInput {
    pub alias: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct CredentialUpdate {
    pub credential: Credential,
    pub changed_fields: Vec<&'static str>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct SecretHeaderInput {
    pub name: String,
    pub value: String,
}

impl RegisterHttpCredentialInput {
    fn into_domain(self) -> RegisterCredentialInput {
        RegisterCredentialInput {
            category: CredentialCategory::Http,
            provider: self.provider,
            alias: self.alias,
            endpoint: self.endpoint,
            secret: CredentialSecret::Http {
                headers: self
                    .secret_headers
                    .into_iter()
                    .map(|header| SecretHeader {
                        name: header.name,
                        value: SecretString::from(header.value),
                    })
                    .collect(),
            },
            description: self.description,
            env: self.env,
            tags: self.tags,
            policy: self.policy,
            allow_private_network: self.allow_private_network,
            tls_server_ca: Some(self.tls_server_ca),
        }
    }
}

impl RegisterSqlCredentialInput {
    fn into_domain(self) -> RegisterCredentialInput {
        RegisterCredentialInput {
            category: CredentialCategory::Sql,
            provider: self.provider,
            alias: self.alias,
            endpoint: self.endpoint,
            secret: CredentialSecret::Sql {
                username: SecretString::from(self.username),
                password: SecretString::from(self.password),
            },
            description: self.description,
            env: self.env,
            tags: self.tags,
            policy: self.policy,
            allow_private_network: self.allow_private_network,
            tls_server_ca: None,
        }
    }
}

#[derive(Clone)]
enum EndpointResolver {
    System,
    #[cfg(test)]
    Fixed(Vec<IpAddr>),
}

impl EndpointResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>> {
        match self {
            Self::System => tokio::net::lookup_host((host, port))
                .await
                .map_err(|error| Error::validation(format!("resolve endpoint host: {error}")))
                .map(|addrs| addrs.map(|addr| addr.ip()).collect()),
            #[cfg(test)]
            Self::Fixed(ips) => Ok(ips.clone()),
        }
    }
}

impl CredentialService {
    async fn validate_register_endpoint_ips(&self, input: &RegisterCredentialInput) -> Result<()> {
        if input.allow_private_network {
            return Ok(());
        }
        let url = url::Url::parse(&input.endpoint)
            .map_err(|error| Error::validation(format!("endpoint URL: {error}")))?;
        let host = url
            .host_str()
            .ok_or_else(|| Error::validation("endpoint requires host"))?;
        let default_port = match input.category {
            CredentialCategory::Http => 443,
            CredentialCategory::Sql => 5432,
        };
        let port = url.port().unwrap_or(default_port);
        let ips = self.resolver.resolve(host, port).await?;
        if ips.is_empty() {
            return Err(Error::validation("resolve endpoint host: no IPs"));
        }
        if ips.into_iter().any(target_ip_is_blocked) {
            return Err(Error::validation(BLOCKED_TARGET_IP_MESSAGE));
        }
        Ok(())
    }
}

fn secret_json(secret: &CredentialSecret) -> Result<Vec<u8>> {
    let value = match secret {
        CredentialSecret::Http { headers } => serde_json::json!({
            "headers": headers.iter().map(secret_header_json).collect::<Vec<_>>()
        }),
        CredentialSecret::Sql { username, password } => serde_json::json!({
            "username": username.expose_secret(),
            "password": password.expose_secret(),
        }),
    };
    serde_json::to_vec(&value)
        .map_err(|error| Error::internal(format!("serialize credential secret: {error}")))
}

fn secret_header_json(header: &SecretHeader) -> serde_json::Value {
    serde_json::json!({
        "name": header.name,
        "value": header.value.expose_secret(),
    })
}

#[derive(Deserialize)]
struct StoredHttpSecret {
    #[serde(default)]
    headers: Vec<StoredSecretHeader>,
}

#[derive(Deserialize)]
struct StoredSecretHeader {
    name: String,
}

fn ensure_update_category(credential: &Credential, expected: CredentialCategory) -> Result<()> {
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

fn validate_http_policy_secret_overlap(
    sealer: &Sealer,
    alias: &str,
    secret_ciphertext: Option<&[u8]>,
    policy: &CredentialPolicy,
) -> Result<()> {
    let ciphertext =
        secret_ciphertext.ok_or_else(|| Error::internal("credential secret missing"))?;
    let plaintext = sealer.open(SECRET_DOMAIN, alias, ciphertext)?;
    let secret = serde_json::from_slice::<StoredHttpSecret>(&plaintext)
        .map_err(|error| Error::internal(format!("decode credential secret: {error}")))?;
    let names = secret
        .headers
        .into_iter()
        .map(|header| header.name)
        .collect::<Vec<_>>();
    validate_allowed_headers_do_not_overlap_secret(policy, &names)
}

fn normalize_list_input(mut input: ListCredentialsInput) -> ListCredentialsInput {
    input.provider = trim_filter_optional(input.provider);
    input.env = trim_filter_optional(input.env);
    input.tag = trim_filter_optional(input.tag).map(|tag| tag.to_ascii_lowercase());
    input.q = trim_filter_optional(input.q);
    input.cursor = trim_filter_optional(input.cursor);
    input.fields = input.fields.map(normalize_list_fields);
    input
}

fn validate_list_input(input: &ListCredentialsInput) -> Result<()> {
    if let Some(provider) = &input.provider {
        validate_credential_provider(provider)?;
    }
    if let Some(env) = &input.env {
        validate_credential_env(env)?;
    }
    if let Some(tag) = &input.tag {
        validate_credential_tag(tag)?;
    }
    if let Some(q) = &input.q
        && (q.len() > MAX_LIST_Q || q.contains(['\r', '\n']))
    {
        return Err(Error::validation(format!(
            "q must be at most {MAX_LIST_Q} characters without CR/LF"
        )));
    }
    if let Some(fields) = &input.fields {
        if fields.len() > MAX_LIST_FIELDS {
            return Err(Error::validation(format!(
                "fields count must be <= {MAX_LIST_FIELDS}"
            )));
        }
        for field in fields {
            if !allowed_list_field(field) {
                return Err(Error::validation(format!("unsupported field {field:?}")));
            }
        }
    }
    if let Some(limit) = input.limit
        && !(1..=MAX_LIST_LIMIT).contains(&limit)
    {
        return Err(Error::validation(format!(
            "limit must be in range [1,{MAX_LIST_LIMIT}]"
        )));
    }
    if let Some(cursor) = &input.cursor {
        validate_credential_alias(cursor)?;
    }
    Ok(())
}

fn normalize_list_fields(fields: Vec<String>) -> Vec<String> {
    if fields.is_empty() {
        return fields;
    }
    let mut out = vec!["alias".to_owned()];
    for field in fields {
        let field = field.trim().to_owned();
        if !field.is_empty() && !out.iter().any(|existing| existing == &field) {
            out.push(field);
        }
    }
    out
}

fn allowed_list_field(field: &str) -> bool {
    matches!(
        field,
        "alias" | "category" | "provider" | "env" | "tags" | "description" | "policy"
    )
}

fn changed_fields(
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

fn register_audit(
    caller: &Caller,
    input: &RegisterCredentialInput,
) -> opsgate_db::CredentialAuditParams {
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
            "has_tls_ca": input.tls_server_ca.is_some(),
        }),
    )
}

fn update_audit(
    caller: &Caller,
    reason: String,
    changed_fields: &[&'static str],
) -> opsgate_db::CredentialAuditParams {
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

fn delete_audit(caller: &Caller, reason: String) -> opsgate_db::CredentialAuditParams {
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

fn trim_optional(value: Option<String>) -> Option<String> {
    value.map(|value| value.trim().to_owned())
}

fn trim_filter_optional(value: Option<String>) -> Option<String> {
    trim_optional(value).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use base64::Engine;
    use chrono::Utc;
    use opsgate_domain::{Channel, User};
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
            endpoint: "https://service.example.test".to_owned(),
            secret_headers: vec![SecretHeaderInput {
                name: "Authorization".to_owned(),
                value: "Bearer secret-token".to_owned(),
            }],
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network,
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
            endpoint: match category {
                CredentialCategory::Http => "https://service.example.test",
                CredentialCategory::Sql => "postgres://db.example.test/app",
            }
            .to_owned(),
            description: "old description".to_owned(),
            env: "prod".to_owned(),
            tags: vec!["prod".to_owned()],
            policy: CredentialPolicy::default(),
            allow_private_network: false,
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
        let err = service
            .validate_register_endpoint_ips(&http_input(false))
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
        let err = service
            .validate_register_endpoint_ips(&http_input(false))
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
            service
                .validate_register_endpoint_ips(&http_input(true))
                .await
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn secret_json_contains_secret_only_before_sealing() -> Result<()> {
        let secret = CredentialSecret::Http {
            headers: vec![SecretHeader {
                name: "Authorization".to_owned(),
                value: SecretString::from("Bearer secret-token".to_owned()),
            }],
        };
        let json = secret_json(&secret)?;
        assert!(String::from_utf8_lossy(&json).contains("secret-token"));

        let key = base64::engine::general_purpose::STANDARD.encode([12_u8; 32]);
        let cipher = opsgate_core::crypto::Cipher::new(&key)?;
        let sealer = Sealer::new(cipher);
        let ciphertext = sealer.seal(SECRET_DOMAIN, "prod", &json)?;
        assert!(!String::from_utf8_lossy(&ciphertext).contains("secret-token"));
        assert!(sealer.open(SECRET_DOMAIN, "other", &ciphertext).is_err());
        Ok(())
    }

    #[test]
    fn register_audit_detail_excludes_endpoint_and_secret_material() {
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
        let ciphertext = sealer.seal(SECRET_DOMAIN, "prod", &secret_json(&secret)?)?;
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
        assert!(validate_list_input(&valid).is_ok());
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
                fields: Some(vec!["allow_private_network".to_owned()]),
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
            assert!(validate_list_input(&normalize_list_input(input)).is_err());
        }
    }
}

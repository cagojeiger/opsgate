use std::collections::BTreeMap;
use std::net::IpAddr;

use opsgate_core::crypto::Sealer;
use opsgate_core::net::ssrf::is_blocked_target_ip;
use opsgate_core::validation::{clamp_i64, validate_reason};
use opsgate_core::{Error, Result};
use opsgate_db::{
    CredentialAuditAction, CredentialAuditParams, CredentialRepo, CredentialSummaryRows,
};
use opsgate_domain::credential::{
    Credential, CredentialCategory, CredentialListParams, CredentialPolicy, CredentialSecret,
    InsertCredentialParams, RegisterCredentialInput, SecretHeader, UpdateCredentialParams,
    normalize_policy_for_category, normalize_register_input, validate_policy_for_category,
    validate_register_input,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use uuid::Uuid;

const SECRET_DOMAIN: &str = "credentials";

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
        owner_user_id: Uuid,
        input: RegisterHttpCredentialInput,
    ) -> Result<Credential> {
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
        let audit = register_audit(owner_user_id, &input);
        self.repo
            .insert_credential(
                InsertCredentialParams {
                    owner_user_id,
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
        owner_user_id: Uuid,
        input: RegisterSqlCredentialInput,
    ) -> Result<Credential> {
        let input = normalize_register_input(input.into_domain());
        validate_register_input(&input)?;
        self.validate_register_endpoint_ips(&input).await?;
        let secret_plaintext = secret_json(&input.secret)?;
        let secret_ciphertext = self
            .sealer
            .seal(SECRET_DOMAIN, &input.alias, &secret_plaintext)?;
        let audit = register_audit(owner_user_id, &input);
        self.repo
            .insert_credential(
                InsertCredentialParams {
                    owner_user_id,
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
        let limit = normalize_limit(input.limit);
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
        owner_user_id: Uuid,
        input: UpdateCredentialInput,
    ) -> Result<CredentialUpdate> {
        self.update(owner_user_id, input, CredentialCategory::Http)
            .await
    }

    pub async fn update_sql(
        &self,
        owner_user_id: Uuid,
        input: UpdateCredentialInput,
    ) -> Result<CredentialUpdate> {
        self.update(owner_user_id, input, CredentialCategory::Sql)
            .await
    }

    pub async fn delete(
        &self,
        owner_user_id: Uuid,
        input: DeleteCredentialInput,
    ) -> Result<Credential> {
        let alias = input.alias.trim().to_owned();
        let reason = validate_reason(&input.reason)?;
        if alias.is_empty() {
            return Err(Error::validation("alias is required"));
        }
        self.repo
            .soft_delete_credential(owner_user_id, &alias, delete_audit(owner_user_id, reason))
            .await
    }

    async fn update(
        &self,
        owner_user_id: Uuid,
        input: UpdateCredentialInput,
        category: CredentialCategory,
    ) -> Result<CredentialUpdate> {
        let alias = input.alias.trim().to_owned();
        let reason = validate_reason(&input.reason)?;
        if alias.is_empty() {
            return Err(Error::validation("alias is required"));
        }

        let description = trim_optional(input.description);
        let env = trim_optional(input.env).map(|env| default_string(&env, "dev"));
        let tags = input.tags.map(normalize_tags);
        let policy = input
            .policy
            .map(|policy| normalize_policy_for_category(policy, category));
        if let Some(policy) = &policy {
            validate_policy_for_category(policy, category)?;
        }

        let changed_fields = changed_fields(&description, &env, &tags, &policy);
        if changed_fields.is_empty() {
            return Err(Error::validation(
                "at least one of description, env, tags, or policy is required",
            ));
        }

        let audit = update_audit(owner_user_id, reason, &changed_fields);
        let credential = self
            .repo
            .update_credential_mutable_fields(
                UpdateCredentialParams {
                    owner_user_id,
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
        if let Some(ip) = ips.into_iter().find(|ip| is_blocked_target_ip(*ip)) {
            return Err(Error::validation(format!(
                "resolved IP {ip} is private/link-local/loopback"
            )));
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

fn normalize_limit(limit: Option<i64>) -> i64 {
    clamp_i64(limit, 50, 1, 100)
}

fn changed_fields(
    description: &Option<String>,
    env: &Option<String>,
    tags: &Option<Vec<String>>,
    policy: &Option<CredentialPolicy>,
) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if description.is_some() {
        fields.push("description");
    }
    if env.is_some() {
        fields.push("env");
    }
    if tags.is_some() {
        fields.push("tags");
    }
    if policy.is_some() {
        fields.push("policy");
    }
    fields
}

fn register_audit(actor_user_id: Uuid, input: &RegisterCredentialInput) -> CredentialAuditParams {
    CredentialAuditParams {
        actor_user_id,
        action: CredentialAuditAction::Register,
        reason: None,
        changed_fields: Vec::new(),
        detail: serde_json::json!({
            "provider": input.provider,
            "env": input.env,
            "tags": input.tags,
            "allow_private_network": input.allow_private_network,
            "has_tls_ca": input.tls_server_ca.is_some(),
        }),
    }
}

fn update_audit(
    actor_user_id: Uuid,
    reason: String,
    changed_fields: &[&'static str],
) -> CredentialAuditParams {
    let changed_fields = changed_fields
        .iter()
        .map(|field| (*field).to_owned())
        .collect::<Vec<_>>();
    CredentialAuditParams {
        actor_user_id,
        action: CredentialAuditAction::Update,
        reason: Some(reason.trim().to_owned()),
        changed_fields: changed_fields.clone(),
        detail: serde_json::json!({
            "changed_fields": changed_fields,
        }),
    }
}

fn delete_audit(actor_user_id: Uuid, reason: String) -> CredentialAuditParams {
    CredentialAuditParams {
        actor_user_id,
        action: CredentialAuditAction::Delete,
        reason: Some(reason.trim().to_owned()),
        changed_fields: Vec::new(),
        detail: serde_json::json!({
            "secret_destroyed": true,
        }),
    }
}

fn trim_optional(value: Option<String>) -> Option<String> {
    value.map(|value| value.trim().to_owned())
}

fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for tag in tags {
        let normalized = tag.trim().to_ascii_lowercase();
        if !normalized.is_empty() && !out.iter().any(|existing| existing == &normalized) {
            out.push(normalized);
        }
    }
    out
}

fn default_string(value: &str, default: &str) -> String {
    if value.is_empty() {
        default.to_owned()
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use base64::Engine;
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
        let audit = register_audit(Uuid::nil(), &input);
        let detail = audit.detail.to_string();

        assert!(matches!(audit.action, CredentialAuditAction::Register));
        assert!(detail.contains("k8s"));
        assert!(!detail.contains("service.example.test"));
        assert!(!detail.contains("secret-token"));
        assert!(!detail.contains("Authorization"));
    }

    #[test]
    fn update_and_delete_audit_store_reason_without_secret_material() {
        let update = update_audit(
            Uuid::nil(),
            "  Allow readonly metadata query  ".to_owned(),
            &["policy"],
        );
        let delete = delete_audit(Uuid::nil(), "  Retire old credential  ".to_owned());

        assert!(matches!(update.action, CredentialAuditAction::Update));
        assert_eq!(
            update.reason.as_deref(),
            Some("Allow readonly metadata query")
        );
        assert!(update.changed_fields.iter().any(|field| field == "policy"));
        assert!(!update.detail.to_string().contains("secret-token"));
        assert!(matches!(delete.action, CredentialAuditAction::Delete));
        assert_eq!(delete.reason.as_deref(), Some("Retire old credential"));
        assert!(!delete.detail.to_string().contains("secret-token"));
    }
}

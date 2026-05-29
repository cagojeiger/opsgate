use std::collections::BTreeMap;
use std::net::IpAddr;

use opsgate_core::crypto::Sealer;
use opsgate_core::net::ssrf::is_blocked_target_ip;
use opsgate_core::{Error, Result};
use opsgate_db::{CredentialRepo, CredentialSummaryRows};
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
}

impl CredentialService {
    pub fn new(repo: CredentialRepo, sealer: Sealer) -> Self {
        Self { repo, sealer }
    }

    pub async fn register_http(
        &self,
        owner_user_id: Uuid,
        input: RegisterHttpCredentialInput,
    ) -> Result<Credential> {
        let input = normalize_register_input(input.into_domain());
        validate_register_input(&input)?;
        validate_register_endpoint_ips(&input).await?;
        let secret_plaintext = secret_json(&input.secret)?;
        let secret_ciphertext = self
            .sealer
            .seal(SECRET_DOMAIN, &input.alias, &secret_plaintext)?;
        let tls_ca = input
            .tls_server_ca
            .as_ref()
            .map(|ca| ca.as_bytes().to_vec());
        self.repo
            .insert_credential(InsertCredentialParams {
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
            })
            .await
    }

    pub async fn register_sql(
        &self,
        owner_user_id: Uuid,
        input: RegisterSqlCredentialInput,
    ) -> Result<Credential> {
        let input = normalize_register_input(input.into_domain());
        validate_register_input(&input)?;
        validate_register_endpoint_ips(&input).await?;
        let secret_plaintext = secret_json(&input.secret)?;
        let secret_ciphertext = self
            .sealer
            .seal(SECRET_DOMAIN, &input.alias, &secret_plaintext)?;
        self.repo
            .insert_credential(InsertCredentialParams {
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
            })
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
        validate_reason(&input.reason)?;
        if alias.is_empty() {
            return Err(Error::validation("alias is required"));
        }
        self.repo
            .soft_delete_credential(owner_user_id, &alias)
            .await
    }

    async fn update(
        &self,
        owner_user_id: Uuid,
        input: UpdateCredentialInput,
        category: CredentialCategory,
    ) -> Result<CredentialUpdate> {
        let alias = input.alias.trim().to_owned();
        validate_reason(&input.reason)?;
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

        let credential = self
            .repo
            .update_credential_mutable_fields(UpdateCredentialParams {
                owner_user_id,
                alias,
                category,
                description,
                env,
                tags,
                policy,
            })
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

async fn validate_register_endpoint_ips(input: &RegisterCredentialInput) -> Result<()> {
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
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| Error::validation(format!("resolve endpoint host: {error}")))?;
    let ips = addrs.map(|addr| addr.ip()).collect::<Vec<_>>();
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
    limit.unwrap_or(50).clamp(1, 100)
}

fn validate_reason(reason: &str) -> Result<()> {
    let reason = reason.trim();
    if reason.len() < 8 || reason.len() > 512 || reason.contains(['\r', '\n']) {
        return Err(Error::validation(
            "reason must be 8-512 characters without CR/LF",
        ));
    }
    Ok(())
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

#[allow(dead_code)]
fn _assert_ipaddr(_: IpAddr) {}

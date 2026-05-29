use std::net::IpAddr;

use opsgate_core::crypto::Sealer;
use opsgate_core::net::ssrf::is_blocked_target_ip;
use opsgate_core::{Error, Result};
use opsgate_db::CredentialRepo;
use opsgate_domain::credential::{
    Credential, CredentialCategory, CredentialListParams, CredentialPolicy, CredentialSecret,
    InsertCredentialParams, RegisterCredentialInput, SecretHeader, normalize_register_input,
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
    ) -> Result<Vec<Credential>> {
        self.repo
            .list_credentials(CredentialListParams {
                owner_user_id,
                category: input.category,
                provider: input.provider,
                env: input.env,
                tag: input.tag,
                q: input.q,
                limit: input.limit.unwrap_or(50),
            })
            .await
    }
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct ListCredentialsInput {
    pub category: Option<CredentialCategory>,
    pub provider: Option<String>,
    pub env: Option<String>,
    pub tag: Option<String>,
    pub q: Option<String>,
    pub limit: Option<i64>,
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

#[allow(dead_code)]
fn _assert_ipaddr(_: IpAddr) {}

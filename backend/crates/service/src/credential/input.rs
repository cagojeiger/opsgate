use opsgate_model::credential::{
    CredentialCategory, CredentialPolicy, CredentialSecret, CredentialTarget,
    RegisterCredentialInput, SecretHeader,
};
use secrecy::SecretString;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct ListCredentialsInput {
    /// Optional category filter: http or sql.
    pub category: Option<CredentialCategory>,
    /// Optional provider filter, e.g. k8s or postgres.
    pub provider: Option<String>,
    /// Optional environment filter such as local, dev, prod.
    pub env: Option<String>,
    /// Optional tag filter.
    pub tag: Option<String>,
    /// Optional text search over alias/provider/description/tags.
    pub q: Option<String>,
    /// Optional output field selection for compact results.
    pub fields: Option<Vec<String>>,
    /// Page size.
    pub limit: Option<i64>,
    /// Cursor returned by a previous list response.
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct RegisterHttpCredentialInput {
    /// Provider label for grouping, e.g. k8s, github, internal-api.
    pub provider: String,
    /// Stable short name used later by api.call.
    pub alias: String,
    /// Scheme and host only, e.g. https://k8s.example.com. Do not include request paths.
    pub origin: String,
    /// Optional fixed path prefix hidden from api.call, e.g. /cluster-a.
    #[serde(default)]
    pub base_path: String,
    /// HTTP header target auth attached to every api.call. Values are sealed and never returned.
    /// May be omitted or empty when client_cert_pem/client_key_pem provide mTLS auth.
    #[serde(default)]
    pub secret_headers: Vec<SecretHeaderInput>,
    /// Human description shown by credential.list.
    #[serde(default)]
    pub description: String,
    /// Environment label such as local, dev, prod.
    #[serde(default)]
    pub env: String,
    /// Search/grouping labels.
    #[serde(default)]
    pub tags: Vec<String>,
    /// HTTP policy: methods, request_path prefixes, query/header constraints, and budgets.
    #[serde(default)]
    pub policy: CredentialPolicy,
    /// Opt in only for trusted private-network targets.
    #[serde(default)]
    pub allow_private_network: bool,
    /// Opt in only when plain HTTP is intentionally needed. HTTPS certificate
    /// verification is not disabled; provide tls_server_ca for self-signed/private CAs.
    #[serde(default)]
    pub allow_insecure_transport: bool,
    /// PEM CA bundle for private HTTPS servers. Leave empty for public WebPKI.
    #[serde(default)]
    pub tls_server_ca: String,
    /// PEM client certificate chain for mutual-TLS targets (e.g. Kubernetes API
    /// servers using client-certificate auth). Requires client_key_pem. Stored
    /// as certificate material and never returned. Leave empty when not using
    /// client certs.
    #[serde(default)]
    pub client_cert_pem: String,
    /// PEM private key matching client_cert_pem. Requires client_cert_pem.
    /// Sealed at rest with the master key and never returned. Leave empty when
    /// not using client certs.
    #[serde(default)]
    pub client_key_pem: String,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct RegisterSqlCredentialInput {
    /// Provider label for grouping. Defaults to postgres when empty.
    #[serde(default)]
    pub provider: String,
    /// Stable short name used later by sql.schema and sql.query.
    pub alias: String,
    /// Postgres target URL without username/password, e.g. postgres://db.example.com/app?sslmode=require.
    pub database_url: String,
    /// Database username. Sealed and never returned.
    pub username: String,
    /// Database password. Sealed and never returned.
    pub password: String,
    /// Human description shown by credential.list.
    #[serde(default)]
    pub description: String,
    /// Environment label such as local, dev, prod.
    #[serde(default)]
    pub env: String,
    /// Search/grouping labels.
    #[serde(default)]
    pub tags: Vec<String>,
    /// SQL policy: metadata/explain permissions, denied functions, and row/byte/time budgets.
    #[serde(default)]
    pub policy: CredentialPolicy,
    /// Opt in only for trusted private-network databases.
    #[serde(default)]
    pub allow_private_network: bool,
    /// Opt in only when non-TLS Postgres is intentionally needed on trusted private networks.
    #[serde(default)]
    pub allow_insecure_transport: bool,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct UpdateCredentialInput {
    /// Existing alias to update.
    pub alias: String,
    /// Human reason for the change; stored in audit/history.
    pub reason: String,
    /// Replace description when present.
    pub description: Option<String>,
    /// Replace environment label when present.
    pub env: Option<String>,
    /// Replace tags when present.
    pub tags: Option<Vec<String>>,
    /// Replace policy when present. Target and secrets cannot be changed here.
    pub policy: Option<CredentialPolicy>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct DeleteCredentialInput {
    /// Existing alias to delete.
    pub alias: String,
    /// Human reason for deletion; stored in audit/history.
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct SecretHeaderInput {
    /// Header name, e.g. Authorization or X-API-Key.
    pub name: String,
    /// Header value. It is sealed on write and never returned.
    pub value: String,
}

impl RegisterHttpCredentialInput {
    pub(super) fn into_domain(self) -> RegisterCredentialInput {
        RegisterCredentialInput {
            category: CredentialCategory::Http,
            provider: self.provider,
            alias: self.alias,
            target: CredentialTarget::Http {
                origin: self.origin,
                base_path: self.base_path,
            },
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
            allow_insecure_transport: self.allow_insecure_transport,
            tls_server_ca: Some(self.tls_server_ca),
            client_cert_pem: Some(self.client_cert_pem),
            client_key_pem: Some(self.client_key_pem),
        }
    }
}

impl RegisterSqlCredentialInput {
    pub(super) fn into_domain(self) -> RegisterCredentialInput {
        RegisterCredentialInput {
            category: CredentialCategory::Sql,
            provider: self.provider,
            alias: self.alias,
            target: CredentialTarget::Sql {
                database_url: self.database_url,
            },
            secret: CredentialSecret::Sql {
                username: SecretString::from(self.username),
                password: SecretString::from(self.password),
            },
            description: self.description,
            env: self.env,
            tags: self.tags,
            policy: self.policy,
            allow_private_network: self.allow_private_network,
            allow_insecure_transport: self.allow_insecure_transport,
            tls_server_ca: None,
            client_cert_pem: None,
            client_key_pem: None,
        }
    }
}

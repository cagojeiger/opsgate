//! Shared application state injected into every handler.

use std::sync::Arc;

use opsgate_core::Config;
use opsgate_db::PgPool;

use crate::api_call::ApiCallService;
use crate::credential::CredentialService;
use crate::identity::CallerResolver;
use crate::sql_schema::SqlSchemaService;

use crate::auth::jwks::JwksCache;
use crate::auth::oidc::OidcProvider;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    pub jwks: Arc<JwksCache>,
    pub oidc: Arc<OidcProvider>,
    pub resolver: Arc<dyn CallerResolver>,
    pub credentials: Arc<CredentialService>,
    pub api_calls: Arc<ApiCallService>,
    pub sql_schema: Arc<SqlSchemaService>,
    pub audit: Arc<opsgate_db::AuditRepo>,
    pub http: reqwest::Client,
}

pub struct AppStateDeps {
    pub db: PgPool,
    pub config: Arc<Config>,
    pub jwks: Arc<JwksCache>,
    pub oidc: Arc<OidcProvider>,
    pub resolver: Arc<dyn CallerResolver>,
    pub credentials: Arc<CredentialService>,
    pub api_calls: Arc<ApiCallService>,
    pub sql_schema: Arc<SqlSchemaService>,
    pub audit: Arc<opsgate_db::AuditRepo>,
    pub http: reqwest::Client,
}

impl AppState {
    pub fn new(deps: AppStateDeps) -> Self {
        Self {
            db: deps.db,
            config: deps.config,
            jwks: deps.jwks,
            oidc: deps.oidc,
            resolver: deps.resolver,
            credentials: deps.credentials,
            api_calls: deps.api_calls,
            sql_schema: deps.sql_schema,
            audit: deps.audit,
            http: deps.http,
        }
    }
}

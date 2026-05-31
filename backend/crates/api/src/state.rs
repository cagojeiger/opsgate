//! Shared application state injected into every handler.

use std::sync::Arc;

use axum::extract::FromRef;
use opsgate_core::Config;
use opsgate_db::PgPool;

use crate::api_call::ApiCallService;
use crate::credential::CredentialService;
use crate::identity::CallerResolver;
use crate::sql_query::SqlQueryService;
use crate::sql_schema::SqlSchemaService;

use crate::auth::jwks::JwksCache;
use crate::auth::oidc::OidcProvider;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: PgPool,
    pub(crate) config: Arc<Config>,
    pub(crate) auth: AuthState,
    pub(crate) tools: ToolState,
    pub(crate) audit: Arc<opsgate_db::AuditRepo>,
    pub(crate) http: reqwest::Client,
}

#[derive(Clone)]
pub(crate) struct AuthState {
    pub(crate) jwks: Arc<JwksCache>,
    pub(crate) oidc: Arc<OidcProvider>,
    pub(crate) resolver: Arc<dyn CallerResolver>,
}

#[derive(Clone)]
pub(crate) struct ToolState {
    pub(crate) credentials: Arc<CredentialService>,
    pub(crate) api_calls: Arc<ApiCallService>,
    pub(crate) sql_schema: Arc<SqlSchemaService>,
    pub(crate) sql_query: Arc<SqlQueryService>,
}

impl FromRef<AppState> for Arc<Config> {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}

impl FromRef<AppState> for PgPool {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

//! Shared application state injected into every handler.

use std::sync::Arc;

use opsgate_core::Config;
use opsgate_db::PgPool;

use crate::identity::CallerResolver;

use crate::auth::jwks::JwksCache;
use crate::auth::oidc::OidcProvider;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    pub jwks: Arc<JwksCache>,
    pub oidc: Arc<OidcProvider>,
    pub resolver: Arc<dyn CallerResolver>,
    pub http: reqwest::Client,
}

impl AppState {
    pub fn new(
        db: PgPool,
        config: Arc<Config>,
        jwks: Arc<JwksCache>,
        oidc: Arc<OidcProvider>,
        resolver: Arc<dyn CallerResolver>,
        http: reqwest::Client,
    ) -> Self {
        Self {
            db,
            config,
            jwks,
            oidc,
            resolver,
            http,
        }
    }
}

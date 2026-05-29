//! Cached OIDC client construction.
//!
//! Provider discovery (`.well-known/openid-configuration`) returns endpoint
//! addresses that change far less often than signing keys (those are handled
//! separately by [`crate::auth::jwks::JwksCache`]). So instead of discovering
//! on every login/callback, we cache the discovered metadata with a generous
//! TTL and rebuild the (cheap, network-free) client per request from it.

use std::time::{Duration, Instant};

use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::{AuthType, ClientId, IssuerUrl, RedirectUrl};
use tokio::sync::RwLock;

/// How long discovered provider metadata stays fresh. An hour bounds staleness
/// (so an authgate endpoint change is absorbed without a restart) while keeping
/// the per-login discovery cost effectively zero.
const METADATA_CACHE_TTL: Duration = Duration::from_secs(3600);

pub(crate) type OidcClient = CoreClient<
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

pub(crate) struct OidcProvider {
    issuer: String,
    client_id: String,
    redirect_url: String,
    http: reqwest::Client,
    cache: RwLock<Option<CachedMetadata>>,
}

#[derive(Clone)]
struct CachedMetadata {
    metadata: CoreProviderMetadata,
    fetched_at: Instant,
}

impl OidcProvider {
    pub(crate) fn new(config: &opsgate_core::Config, http: reqwest::Client) -> Self {
        Self {
            issuer: config.authgate_url.clone(),
            client_id: config.oauth_client_id.clone(),
            redirect_url: config.oauth_redirect_url.clone(),
            http,
            cache: RwLock::new(None),
        }
    }

    /// Build an OIDC client from cached (or freshly discovered) provider metadata.
    pub(crate) async fn client(&self) -> opsgate_core::Result<OidcClient> {
        let metadata = self.metadata().await?;
        let client =
            CoreClient::from_provider_metadata(metadata, ClientId::new(self.client_id.clone()), None)
                .set_redirect_uri(RedirectUrl::new(self.redirect_url.clone()).map_err(|error| {
                    opsgate_core::Error::validation(format!("invalid redirect URL: {error}"))
                })?)
                .set_auth_type(AuthType::RequestBody);
        Ok(client)
    }

    async fn metadata(&self) -> opsgate_core::Result<CoreProviderMetadata> {
        let snapshot = { self.cache.read().await.clone() };
        if let Some(cached) = &snapshot
            && cached.fetched_at.elapsed() <= METADATA_CACHE_TTL
        {
            return Ok(cached.metadata.clone());
        }

        match self.refresh().await {
            Ok(metadata) => Ok(metadata),
            Err(error) => match snapshot {
                // Serve stale metadata if discovery is momentarily unavailable;
                // endpoints rarely change, so this keeps logins working.
                Some(cached) => {
                    tracing::warn!(event = "oidc.discovery_stale", %error);
                    Ok(cached.metadata)
                }
                None => Err(error),
            },
        }
    }

    async fn refresh(&self) -> opsgate_core::Result<CoreProviderMetadata> {
        let issuer = IssuerUrl::new(self.issuer.clone())
            .map_err(|error| opsgate_core::Error::validation(format!("invalid issuer URL: {error}")))?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &self.http)
            .await
            .map_err(|error| {
                opsgate_core::Error::internal(format!("openid discovery failed: {error}"))
            })?;
        {
            let mut guard = self.cache.write().await;
            *guard = Some(CachedMetadata {
                metadata: metadata.clone(),
                fetched_at: Instant::now(),
            });
        }
        Ok(metadata)
    }
}

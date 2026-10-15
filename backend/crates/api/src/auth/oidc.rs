//! Cached OIDC client construction.
//!
//! Provider discovery (`.well-known/openid-configuration`) returns endpoint
//! addresses and a signing-key snapshot. Cache discovery for an hour; a browser
//! ID token with a missing key or invalid signature can refresh only the JWKS.
//! The bearer JWT verifier has its own independent cache.

use std::time::{Duration, Instant};

use openidconnect::core::{CoreClient, CoreJsonWebKeySet, CoreProviderMetadata};
use openidconnect::{AuthType, ClientId, IssuerUrl, RedirectUrl};
use tokio::sync::{Mutex, RwLock};

/// Refresh discovery after an hour. Failed discovery may keep serving an older
/// snapshot, so this freshness interval is not a maximum key-trust lifetime.
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
    cache: RwLock<MetadataCache>,
    refresh: Mutex<()>,
}

#[derive(Clone, Default)]
struct MetadataCache {
    cached: Option<CachedMetadata>,
    attempt: u64,
    failure: Option<String>,
}

pub(super) struct OidcSnapshot {
    cached: CachedMetadata,
    attempt: u64,
}

#[derive(Clone)]
struct CachedMetadata {
    metadata: CoreProviderMetadata,
    fetched_at: Instant,
}

impl OidcProvider {
    pub(crate) fn new(config: &crate::config::Config, http: reqwest::Client) -> Self {
        Self {
            issuer: config.authgate_url.clone(),
            client_id: config.oauth_client_id.clone(),
            redirect_url: config.oauth_redirect_url.clone(),
            http,
            cache: RwLock::new(MetadataCache::default()),
            refresh: Mutex::new(()),
        }
    }

    /// Build an OIDC client from cached (or freshly discovered) provider metadata.
    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub(crate) async fn client(&self) -> opsgate_core::Result<OidcClient> {
        self.client_with_snapshot().await.map(|(client, _)| client)
    }

    pub(super) async fn client_with_snapshot(
        &self,
    ) -> opsgate_core::Result<(OidcClient, OidcSnapshot)> {
        let snapshot = self.metadata().await?;
        let client = self.build_client(snapshot.cached.metadata.clone())?;
        Ok((client, snapshot))
    }

    fn build_client(&self, metadata: CoreProviderMetadata) -> opsgate_core::Result<OidcClient> {
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(self.client_id.clone()),
            None,
        )
        .set_redirect_uri(
            RedirectUrl::new(self.redirect_url.clone()).map_err(|error| {
                opsgate_core::Error::validation(format!("invalid redirect URL: {error}"))
            })?,
        )
        .set_auth_type(AuthType::RequestBody);
        Ok(client)
    }

    async fn metadata(&self) -> opsgate_core::Result<OidcSnapshot> {
        let observed = self.cache.read().await.clone();
        if let Some(cached) = &observed.cached
            && cached.fetched_at.elapsed() <= METADATA_CACHE_TTL
        {
            return snapshot(observed);
        }

        // Only the refresh gate spans I/O. Warm-cache readers never wait for it.
        let _refresh = self.refresh.lock().await;
        let current = self.cache.read().await.clone();
        if current.attempt != observed.attempt
            || current
                .cached
                .as_ref()
                .is_some_and(|cached| cached.fetched_at.elapsed() <= METADATA_CACHE_TTL)
        {
            return snapshot(current);
        }

        let result = self.discover().await;
        let mut cache = self.cache.write().await;
        cache.attempt = cache.attempt.wrapping_add(1);
        match result {
            Ok(metadata) => {
                cache.cached = Some(CachedMetadata {
                    metadata,
                    fetched_at: Instant::now(),
                });
                cache.failure = None;
            }
            Err(error) => {
                cache.failure = Some(error.to_string());
                if cache.cached.is_none() {
                    return Err(error);
                }
                // Preserve the existing discovery-failure stale-cache policy.
                tracing::warn!(event = "oidc.discovery_stale", %error);
            }
        }
        snapshot(cache.clone())
    }

    /// Refresh keys from the URI in the verified discovery snapshot, at most
    /// once for callbacks that observed the same refresh attempt.
    pub(super) async fn refresh_jwks(
        &self,
        observed: &OidcSnapshot,
    ) -> opsgate_core::Result<OidcClient> {
        let _refresh = self.refresh.lock().await;
        let current = self.cache.read().await.clone();
        if current.attempt != observed.attempt {
            // A later failed refresh can still leave newer, usable keys cached.
            // Verify this token with that snapshot rather than replaying its error.
            return self.build_client(snapshot(current)?.cached.metadata);
        }

        let result =
            CoreJsonWebKeySet::fetch_async(observed.cached.metadata.jwks_uri(), &self.http).await;
        let mut cache = self.cache.write().await;
        // Failed attempts advance too, so waiting callbacks share the failure.
        cache.attempt = cache.attempt.wrapping_add(1);
        match result {
            Ok(jwks) => {
                let metadata = observed.cached.metadata.clone().set_jwks(jwks);
                cache.cached = Some(CachedMetadata {
                    metadata: metadata.clone(),
                    // Key refresh must not extend the discovery endpoint TTL.
                    fetched_at: observed.cached.fetched_at,
                });
                cache.failure = None;
                self.build_client(metadata)
            }
            Err(error) => {
                let message = format!("openid JWKS refresh failed: {error}");
                cache.failure = Some(message.clone());
                Err(opsgate_core::Error::internal(message))
            }
        }
    }

    async fn discover(&self) -> opsgate_core::Result<CoreProviderMetadata> {
        let issuer = IssuerUrl::new(self.issuer.clone()).map_err(|error| {
            opsgate_core::Error::validation(format!("invalid issuer URL: {error}"))
        })?;
        CoreProviderMetadata::discover_async(issuer, &self.http)
            .await
            .map_err(|error| {
                opsgate_core::Error::internal(format!("openid discovery failed: {error}"))
            })
    }
}

fn snapshot(cache: MetadataCache) -> opsgate_core::Result<OidcSnapshot> {
    let cached = cache.cached.ok_or_else(|| {
        opsgate_core::Error::internal(
            cache
                .failure
                .unwrap_or_else(|| "OIDC metadata unavailable".to_owned()),
        )
    })?;
    Ok(OidcSnapshot {
        cached,
        attempt: cache.attempt,
    })
}

#[cfg(test)]
#[path = "oidc_tests.rs"]
mod tests;

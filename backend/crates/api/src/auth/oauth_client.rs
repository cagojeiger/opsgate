use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::{AuthType, ClientId, IssuerUrl, RedirectUrl};

type OidcClient = CoreClient<
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

pub(super) async fn oidc_client(
    config: &opsgate_core::Config,
    http: &reqwest::Client,
) -> opsgate_core::Result<OidcClient> {
    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(config.authgate_url.clone()).map_err(|error| {
            opsgate_core::Error::validation(format!("invalid issuer URL: {error}"))
        })?,
        http,
    )
    .await
    .map_err(|error| opsgate_core::Error::internal(format!("openid discovery failed: {error}")))?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.oauth_client_id.clone()),
        None,
    )
    .set_redirect_uri(
        RedirectUrl::new(config.oauth_redirect_url.clone()).map_err(|error| {
            opsgate_core::Error::validation(format!("invalid redirect URL: {error}"))
        })?,
    )
    .set_auth_type(AuthType::RequestBody);

    Ok(client)
}

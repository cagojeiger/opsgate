use openidconnect::core::CoreUserInfoClaims;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClaimsVerificationError, Nonce, OAuth2TokenResponse,
    PkceCodeVerifier, SignatureVerificationError, TokenResponse as OidcTokenResponse,
};
use serde::{Deserialize, Serialize};

use crate::auth::oidc::OidcProvider;

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct UserInfo {
    pub(super) sub: String,
    #[serde(default)]
    pub(super) email: Option<String>,
    #[serde(default)]
    pub(super) name: Option<String>,
}

pub(super) async fn exchange_code_for_userinfo(
    oidc: &OidcProvider,
    code: &str,
    verifier: &str,
    nonce: &str,
) -> opsgate_core::Result<UserInfo> {
    let (client, snapshot) = oidc.client_with_snapshot().await?;
    let token_response = client
        .exchange_code(AuthorizationCode::new(code.to_owned()))
        .map_err(|error| {
            opsgate_core::Error::internal(format!("openid token endpoint unavailable: {error}"))
        })?
        .set_pkce_verifier(PkceCodeVerifier::new(verifier.to_owned()))
        .request_async(oidc.http())
        .await
        .map_err(|error| {
            opsgate_core::Error::internal(format!("openid token exchange failed: {error}"))
        })?;

    let id_token = token_response
        .id_token()
        .ok_or_else(|| opsgate_core::Error::internal("openid token response missing id_token"))?;
    let initial_verifier = client.id_token_verifier();
    let nonce = Nonce::new(nonce.to_owned());
    let refreshed_client;
    let refreshed_verifier;
    let (client, id_token_verifier, claims) = match id_token.claims(&initial_verifier, &nonce) {
        Err(ClaimsVerificationError::SignatureVerification(
            SignatureVerificationError::NoMatchingKey | SignatureVerificationError::CryptoError(_),
        )) => {
            // The code is single use: retry only verification of this response.
            refreshed_client = oidc.refresh_jwks(&snapshot).await?;
            refreshed_verifier = refreshed_client.id_token_verifier();
            (
                &refreshed_client,
                &refreshed_verifier,
                id_token.claims(&refreshed_verifier, &nonce),
            )
        }
        result => (&client, &initial_verifier, result),
    };
    let claims = claims.map_err(|error| {
        opsgate_core::Error::internal(format!("id_token verification failed: {error}"))
    })?;

    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            token_response.access_token(),
            id_token.signing_alg().map_err(|error| {
                opsgate_core::Error::internal(format!("id_token signing alg failed: {error}"))
            })?,
            id_token.signing_key(id_token_verifier).map_err(|error| {
                opsgate_core::Error::internal(format!("id_token signing key failed: {error}"))
            })?,
        )
        .map_err(|error| {
            opsgate_core::Error::internal(format!("access token hash failed: {error}"))
        })?;
        if actual_access_token_hash != *expected_access_token_hash {
            return Err(opsgate_core::Error::internal("access token hash mismatch"));
        }
    }

    let userinfo: CoreUserInfoClaims = client
        .user_info(
            token_response.access_token().to_owned(),
            Some(claims.subject().to_owned()),
        )
        .map_err(|error| {
            opsgate_core::Error::internal(format!("userinfo endpoint unavailable: {error}"))
        })?
        .request_async(oidc.http())
        .await
        .map_err(|error| {
            opsgate_core::Error::internal(format!("userinfo request failed: {error}"))
        })?;

    Ok(UserInfo {
        sub: userinfo.subject().as_str().to_owned(),
        email: userinfo.email().map(|email| email.as_str().to_owned()),
        name: userinfo
            .name()
            .and_then(|name| name.get(None))
            .map(|name| name.as_str().to_owned()),
    })
}

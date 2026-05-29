#[cfg(test)]
use std::collections::HashMap;

use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
#[cfg(test)]
use base64::Engine;
#[cfg(test)]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::core::CoreAuthenticationFlow;
use openidconnect::{CsrfToken, Nonce, PkceCodeChallenge, Scope};
#[cfg(test)]
use rand::RngCore;
#[cfg(test)]
use sha2::{Digest, Sha256};
use time::Duration as CookieDuration;
#[cfg(test)]
use url::Url;

use crate::auth::oauth_client::oidc_client;

pub(super) const LOGIN_STATE_COOKIE: &str = "opsgate_login_state";
pub(super) const LOGIN_VERIFIER_COOKIE: &str = "opsgate_login_verifier";
pub(super) const LOGIN_NONCE_COOKIE: &str = "opsgate_login_nonce";
const FLOW_COOKIE_MAX_AGE_SECS: i64 = 300;

pub(super) struct LoginFlow {
    pub redirect_url: String,
    pub csrf_state: String,
    pub pkce_verifier: String,
    pub nonce: String,
}

pub(super) async fn new_login_flow(
    config: &opsgate_core::Config,
    http: &reqwest::Client,
) -> opsgate_core::Result<LoginFlow> {
    let client = oidc_client(config, http).await?;
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (redirect_url, csrf_state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("profile".to_owned()))
        .add_scope(Scope::new("email".to_owned()))
        .add_scope(Scope::new("offline_access".to_owned()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    Ok(LoginFlow {
        redirect_url: redirect_url.to_string(),
        csrf_state: csrf_state.secret().to_owned(),
        pkce_verifier: pkce_verifier.secret().to_owned(),
        nonce: nonce.secret().to_owned(),
    })
}

pub(super) fn flow_cookie(name: &'static str, value: String, secure: bool) -> Cookie<'static> {
    Cookie::build((name, value))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .max_age(CookieDuration::seconds(FLOW_COOKIE_MAX_AGE_SECS))
        .build()
}

pub(super) fn clear_flow_cookies(jar: CookieJar, secure: bool) -> CookieJar {
    jar.add(expired_cookie(LOGIN_STATE_COOKIE, secure))
        .add(expired_cookie(LOGIN_VERIFIER_COOKIE, secure))
        .add(expired_cookie(LOGIN_NONCE_COOKIE, secure))
}

fn expired_cookie(name: &'static str, secure: bool) -> Cookie<'static> {
    Cookie::build((name, ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .max_age(CookieDuration::seconds(0))
        .build()
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

#[cfg(test)]
pub fn new_pkce() -> opsgate_core::Result<Pkce> {
    let mut raw = [0_u8; 48];
    rand::thread_rng().fill_bytes(&mut raw);
    let verifier = URL_SAFE_NO_PAD.encode(raw);
    let challenge = pkce_challenge(&verifier);
    Ok(Pkce {
        verifier,
        challenge,
    })
}

#[cfg(test)]
pub fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
pub fn new_state() -> opsgate_core::Result<String> {
    let mut raw = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

#[cfg(test)]
pub fn authorize_url(config: &opsgate_core::Config, state: &str, challenge: &str) -> String {
    let base = format!("{}/authorize", config.authgate_url);
    let parsed = Url::parse(&base).or_else(|_error| Url::parse("http://localhost/authorize"));
    let mut url = match parsed {
        Ok(url) => url,
        Err(_error) => return base,
    };
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.oauth_client_id)
        .append_pair("redirect_uri", &config.oauth_redirect_url)
        .append_pair("scope", "openid profile email offline_access")
        .append_pair("state", state)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256");
    url.to_string()
}

#[cfg(test)]
pub fn parse_authorize_query(url: &str) -> HashMap<String, String> {
    Url::parse(url)
        .ok()
        .and_then(|url| url.query().map(str::to_owned))
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};

    use super::*;

    fn config() -> opsgate_core::Config {
        opsgate_core::Config {
            bind_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 9091)),
            database_url: "postgres://example".to_owned(),
            db_max_connections: 1,
            authgate_url: "https://auth.example.test".to_owned(),
            opsgate_public_url: "https://api.example.test".to_owned(),
            oauth_client_id: "client".to_owned(),
            oauth_redirect_url: "https://api.example.test/callback".to_owned(),
            resource_url: "https://api.example.test".to_owned(),
            jwks_cache_ttl: std::time::Duration::from_secs(300),
            secure_cookies: true,
        }
    }

    #[test]
    fn pkce_challenge_uses_verifier_string_bytes() -> opsgate_core::Result<()> {
        let pkce = new_pkce()?;
        assert!((43..=128).contains(&pkce.verifier.len()));
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce.verifier.as_bytes()));
        assert_eq!(pkce.challenge, expected);
        Ok(())
    }

    #[test]
    fn state_is_32_random_bytes() -> opsgate_core::Result<()> {
        let a = new_state()?;
        let b = new_state()?;
        assert_ne!(a, b);
        let decoded = URL_SAFE_NO_PAD
            .decode(a.as_bytes())
            .map_err(opsgate_core::Error::internal)?;
        assert_eq!(decoded.len(), 32);
        Ok(())
    }

    #[test]
    fn authorize_url_contains_required_params() {
        let url = authorize_url(&config(), "state", "challenge");
        let params = parse_authorize_query(&url);
        assert_eq!(
            params.get("response_type").map(String::as_str),
            Some("code")
        );
        assert_eq!(params.get("client_id").map(String::as_str), Some("client"));
        assert_eq!(
            params.get("redirect_uri").map(String::as_str),
            Some("https://api.example.test/callback")
        );
        assert_eq!(
            params.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
    }
}

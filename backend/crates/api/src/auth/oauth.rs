#[cfg(test)]
use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration as CookieDuration;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use opsgate_domain::{IdentityError, ResolveAttrs};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;

use crate::auth::page::html_page;
use crate::state::AppState;

const LOGIN_STATE_COOKIE: &str = "opsgate_login_state";
const LOGIN_VERIFIER_COOKIE: &str = "opsgate_login_verifier";
const FLOW_COOKIE_MAX_AGE_SECS: i64 = 300;
const MAX_UPSTREAM_BODY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

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

pub fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn new_state() -> opsgate_core::Result<String> {
    let mut raw = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

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

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserInfo {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

pub async fn login(State(state): State<AppState>, jar: CookieJar) -> Response {
    let pkce = match new_pkce() {
        Ok(pkce) => pkce,
        Err(error) => {
            tracing::error!(event = "oauth.pkce_failed", %error);
            return html_page(StatusCode::INTERNAL_SERVER_ERROR, "Login failed", "internal error");
        }
    };
    let csrf_state = match new_state() {
        Ok(state) => state,
        Err(error) => {
            tracing::error!(event = "oauth.state_failed", %error);
            return html_page(StatusCode::INTERNAL_SERVER_ERROR, "Login failed", "internal error");
        }
    };
    let redirect = authorize_url(&state.config, &csrf_state, &pkce.challenge);
    let jar = jar
        .add(flow_cookie(
            LOGIN_STATE_COOKIE,
            csrf_state,
            state.config.secure_cookies,
        ))
        .add(flow_cookie(
            LOGIN_VERIFIER_COOKIE,
            pkce.verifier,
            state.config.secure_cookies,
        ));
    (jar, Redirect::temporary(&redirect)).into_response()
}

pub async fn callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let cookie_state = jar.get(LOGIN_STATE_COOKIE).map(|cookie| cookie.value().to_owned());
    let cookie_verifier = jar
        .get(LOGIN_VERIFIER_COOKIE)
        .map(|cookie| cookie.value().to_owned());
    let jar = clear_flow_cookies(jar, state.config.secure_cookies);

    if query.error.is_some() {
        return (jar, html_page(StatusCode::BAD_REQUEST, "Login error", "authorization failed"))
            .into_response();
    }

    let (Some(code), Some(query_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return (jar, html_page(StatusCode::BAD_REQUEST, "Login error", "missing code or state"))
            .into_response();
    };

    let Some(cookie_state) = cookie_state else {
        return (jar, html_page(StatusCode::BAD_REQUEST, "Login error", "state mismatch"))
            .into_response();
    };
    if cookie_state.as_bytes().ct_eq(query_state.as_bytes()).unwrap_u8() != 1 {
        return (jar, html_page(StatusCode::BAD_REQUEST, "Login error", "state mismatch"))
            .into_response();
    }

    let Some(verifier) = cookie_verifier.filter(|value| !value.is_empty()) else {
        return (jar, html_page(StatusCode::BAD_REQUEST, "Login error", "missing verifier"))
            .into_response();
    };

    let token = match exchange_code(&state.config, &state.http, code, &verifier).await {
        Ok(token) => token,
        Err(error) => {
            tracing::warn!(event = "oauth.exchange_failed", %error);
            return (jar, html_page(StatusCode::BAD_GATEWAY, "Login error", "token exchange failed"))
                .into_response();
        }
    };
    let userinfo = match userinfo(&state.config, &state.http, &token.access_token).await {
        Ok(userinfo) => userinfo,
        Err(error) => {
            tracing::warn!(event = "oauth.userinfo_failed", %error);
            return (jar, html_page(StatusCode::BAD_GATEWAY, "Login error", "userinfo failed"))
                .into_response();
        }
    };
    let attrs = ResolveAttrs {
        sub: userinfo.sub,
        email: userinfo.email.unwrap_or_default(),
        name: userinfo.name.unwrap_or_default(),
    };
    match state.resolver.resolve_browser(attrs.clone()).await {
        Ok(_caller) => {
            let body = format!(
                "You're registered, sub={}. Reconnect your MCP client to {}.",
                attrs.sub, state.config.resource_url
            );
            (jar, html_page(StatusCode::OK, "Login complete", &body)).into_response()
        }
        Err(IdentityError::NotAdmin) => (
            jar,
            html_page(StatusCode::FORBIDDEN, "Login forbidden", "email not on admin allowlist"),
        )
            .into_response(),
        Err(IdentityError::Inactive) => (
            jar,
            html_page(StatusCode::FORBIDDEN, "Login forbidden", "user is inactive"),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(event = "oauth.resolve_failed", %error);
            (jar, html_page(StatusCode::INTERNAL_SERVER_ERROR, "Login error", "internal error"))
                .into_response()
        }
    }
}

pub async fn exchange_code(
    config: &opsgate_core::Config,
    http: &reqwest::Client,
    code: &str,
    verifier: &str,
) -> opsgate_core::Result<TokenResponse> {
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &config.oauth_redirect_url),
        ("client_id", &config.oauth_client_id),
        ("code_verifier", verifier),
    ];
    let response = http
        .post(format!("{}/oauth/token", config.authgate_url))
        .form(&form)
        .send()
        .await
        .map_err(|error| opsgate_core::Error::internal(format!("token request failed: {error}")))?;
    if !response.status().is_success() {
        return Err(opsgate_core::Error::internal(format!(
            "token endpoint returned {}",
            response.status()
        )));
    }
    let body = response
        .bytes()
        .await
        .map_err(|error| opsgate_core::Error::internal(format!("token body failed: {error}")))?;
    if body.len() as u64 > MAX_UPSTREAM_BODY_BYTES {
        return Err(opsgate_core::Error::internal("token body too large"));
    }
    let token: TokenResponse = serde_json::from_slice(&body)
        .map_err(|error| opsgate_core::Error::internal(format!("token json failed: {error}")))?;
    if token.access_token.is_empty() {
        return Err(opsgate_core::Error::internal("token response missing access_token"));
    }
    Ok(token)
}

pub async fn userinfo(
    config: &opsgate_core::Config,
    http: &reqwest::Client,
    access_token: &str,
) -> opsgate_core::Result<UserInfo> {
    let response = http
        .get(format!("{}/userinfo", config.authgate_url))
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|error| opsgate_core::Error::internal(format!("userinfo request failed: {error}")))?;
    if !response.status().is_success() {
        return Err(opsgate_core::Error::internal(format!(
            "userinfo endpoint returned {}",
            response.status()
        )));
    }
    let body = response
        .bytes()
        .await
        .map_err(|error| opsgate_core::Error::internal(format!("userinfo body failed: {error}")))?;
    if body.len() as u64 > MAX_UPSTREAM_BODY_BYTES {
        return Err(opsgate_core::Error::internal("userinfo body too large"));
    }
    let userinfo: UserInfo = serde_json::from_slice(&body)
        .map_err(|error| opsgate_core::Error::internal(format!("userinfo json failed: {error}")))?;
    if userinfo.sub.is_empty() {
        return Err(opsgate_core::Error::internal("userinfo response missing sub"));
    }
    Ok(userinfo)
}

fn flow_cookie(name: &'static str, value: String, secure: bool) -> Cookie<'static> {
    Cookie::build((name, value))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .max_age(CookieDuration::seconds(FLOW_COOKIE_MAX_AGE_SECS))
        .build()
}

fn clear_flow_cookies(jar: CookieJar, secure: bool) -> CookieJar {
    jar.add(expired_cookie(LOGIN_STATE_COOKIE, secure))
        .add(expired_cookie(LOGIN_VERIFIER_COOKIE, secure))
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
pub fn parse_authorize_query(url: &str) -> HashMap<String, String> {
    Url::parse(url)
        .ok()
        .and_then(|url| url.query().map(str::to_owned))
        .map(|query| url::form_urlencoded::parse(query.as_bytes()).into_owned().collect())
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
            admin_email: "admin@example.test".to_owned(),
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
        let decoded = URL_SAFE_NO_PAD.decode(a.as_bytes()).map_err(opsgate_core::Error::internal)?;
        assert_eq!(decoded.len(), 32);
        Ok(())
    }

    #[test]
    fn authorize_url_contains_required_params() {
        let url = authorize_url(&config(), "state", "challenge");
        let params = parse_authorize_query(&url);
        assert_eq!(params.get("response_type").map(String::as_str), Some("code"));
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

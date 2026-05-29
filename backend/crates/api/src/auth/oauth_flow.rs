use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use openidconnect::core::CoreAuthenticationFlow;
use openidconnect::{CsrfToken, Nonce, PkceCodeChallenge, Scope};
use time::Duration as CookieDuration;

use crate::auth::oidc::OidcProvider;

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

pub(super) async fn new_login_flow(oidc: &OidcProvider) -> opsgate_core::Result<LoginFlow> {
    let client = oidc.client().await?;
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
mod tests {
    use axum_extra::extract::CookieJar;
    use axum_extra::extract::cookie::SameSite;
    use time::Duration as CookieDuration;

    use super::{
        LOGIN_NONCE_COOKIE, LOGIN_STATE_COOKIE, LOGIN_VERIFIER_COOKIE, clear_flow_cookies,
        flow_cookie,
    };

    #[test]
    fn flow_cookie_is_hardened_with_max_age() {
        let cookie = flow_cookie(LOGIN_STATE_COOKIE, "value".to_owned(), true);
        assert_eq!(cookie.name(), LOGIN_STATE_COOKIE);
        assert_eq!(cookie.value(), "value");
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.max_age(), Some(CookieDuration::seconds(300)));
    }

    #[test]
    fn insecure_flow_cookie_drops_secure_flag() {
        let cookie = flow_cookie(LOGIN_STATE_COOKIE, "value".to_owned(), false);
        assert_eq!(cookie.secure(), Some(false));
    }

    #[test]
    fn clear_flow_cookies_expires_every_login_cookie() -> Result<(), Box<dyn std::error::Error>> {
        let jar = clear_flow_cookies(CookieJar::new(), true);
        for name in [
            LOGIN_STATE_COOKIE,
            LOGIN_VERIFIER_COOKIE,
            LOGIN_NONCE_COOKIE,
        ] {
            let cookie = jar.get(name).ok_or("expired cookie missing from jar")?;
            assert_eq!(cookie.value(), "");
            assert_eq!(cookie.max_age(), Some(CookieDuration::seconds(0)));
        }
        Ok(())
    }
}

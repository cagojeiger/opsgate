use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use opsgate_domain::{Caller, Channel, IdentityError, ResolveAttrs, User};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use crate::auth::jwks::JwksCache;
use crate::identity::CallerResolver;
use crate::state::AppState;

use crate::auth::bearer::{RequestMeta, verify_bearer};
use crate::auth::bearer_error::AuthError;

const KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCx8TUdJX0WeXTQ
I4bxI8S08Y4xr3k/hcyGmydJXiVt+hQXK4CM9Rz+4W2SYfazdWg0p1h0eyL883Jy
9LmxfQs44T1mifs7CZlm8ihxmZj3unsFQAA7hd9fGHwwNbVQrMGzAb7tNV6REoBs
800pSMl6Bta0VgStT/taUXwKsJfl5sN/KOS4ZQf5thFGdF3XSlf89MhDrXn0V0np
H3CA0iTSBE1EexYR2VX4DGE8CZhc9YU29ikO2I2UKLdqcKnyROVbMsop4l1YEfOv
fG4HJQZctx8IihWwF35Je2lLrYTamS3wPw6K1zFwT3/wNlxcHtn5MiPnji4Bjddo
9OZ4o9x3AgMBAAECggEAOsPhmiAU2PTAjrKE8KMy5dz2bFM6lC9wVa3swg6dBt51
fxdnS2Xxrv0szhCbRDYMdYMks8cszWPq0qsenk6hA6ZjPDdqaFtptXVYxPeIbJvB
4AB8cyvpkoLIFLXQDPYYvDDh6H3dHsUA87pAK9e1bh7PDlxwC/qjlHbfo7ohWBOZ
YzpsNeAhP3COpnhrkUTRoeBKV18T8p320VJ5fCVbK0w+vGEgw/8gWql3POjBUbb+
/N2dKXDLePXB94HjS6YLz0/Zvb9oMsDDiyOoC/1jXYXLHdKEbOPgW1KVjwmQp2ro
gA6mqK4fUSQ89pvqDzHpC3UGoSjSRvgwgoOJ/E18HQKBgQDvzovIWlpbIF9n4FGX
uq+mZa0fhcjyfe8p1YuDTAUJYuEx4CyoJDXuEil8yDvR1rYmPpqbGDArQlBtw67j
37m4+Cm0iRUHjlUUdwHHJggytRWeIq7AqAaPepjxdZAjV/6k1zIA2eGa8pK141rS
eBS22nreobqmhNWJ0hyicpO6mwKBgQC99Tr5b4aB3voVKG2cAG/ps2hrk70RKwcZ
yVd2xtN3iAGvvlG9UozpI7Unkm69jyHwwJTTVxYXD5Na1BbulUBNbJo7Ro1tzAtx
KvgZB6q2Li9HT84FzvZ29tQfQr9zxdnnunpptBip9oBCEK3yDBDmZXzzkwjKp7cY
zF85O4OlVQKBgDHPuG9UfUJCdi7QhII8z/GDWzOaCYR9LimFZuZN6xnpBRfkFcKT
SvR5p055FRvgOpO1G04t9wt1SdmS9Qf2V9CZE6ihdNHN+dQ3aBIizz8hKC1hzOTN
whcZgx1cqyT8STOaU5Ojrl4OFvVbFWl0cfENbspB09B09Rocn8AKhq8TAoGAJdwo
ouptfpj4cxsZrYwQwh115GsPtcpDogoVGqFKKHq9C0/9bqRzXUw2oOp4k+NhOmDH
yM+EoZgDIIlBANBSfpv0qXfIXGfcp/OOez6h8amG1sm7IEE9sjxDzu84xVRbt+nc
2BCDEe0FZyV35dQt0h3MJ6fYiruerJyfJgMMm/kCgYBnqQ5mEiA76yh/208g1nfM
WNYy7n/b2QYI1CcDUtrxjmDVGSbdQ1MG04Az3PhLBDh4UE/yOXb3slpLECmfjcK/
lq0mdqBAHuT8W8E2jRw9CejdITWxllSS0L8xhhSv5JMJ+3CUmpbsWP1X6ByQmF/E
EmW0T9kajxWyy7ochOgNdA==
-----END PRIVATE KEY-----"#;

const PUB_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsfE1HSV9Fnl00COG8SPE
tPGOMa95P4XMhpsnSV4lbfoUFyuAjPUc/uFtkmH2s3VoNKdYdHsi/PNycvS5sX0L
OOE9Zon7OwmZZvIocZmY97p7BUAAO4XfXxh8MDW1UKzBswG+7TVekRKAbPNNKUjJ
egbWtFYErU/7WlF8CrCX5ebDfyjkuGUH+bYRRnRd10pX/PTIQ6159FdJ6R9wgNIk
0gRNRHsWEdlV+AxhPAmYXPWFNvYpDtiNlCi3anCp8kTlWzLKKeJdWBHzr3xuByUG
XLcfCIoVsBd+SXtpS62E2pkt8D8OitcxcE9/8DZcXB7Z+TIj544uAY3XaPTmeKPc
dwIDAQAB
-----END PUBLIC KEY-----"#;

#[derive(Debug, Serialize)]
struct TestClaims {
    sub: String,
    email: String,
    name: String,
    iss: String,
    aud: Value,
    exp: usize,
}

#[derive(Clone)]
struct TestResolver {
    mode: ResolverMode,
}

#[derive(Clone)]
enum ResolverMode {
    Registered(bool),
    Missing,
}

impl CallerResolver for TestResolver {
    fn resolve_browser(
        &self,
        attrs: ResolveAttrs,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, IdentityError>> + Send + '_>> {
        self.resolve_api(attrs)
    }

    fn resolve_api(
        &self,
        attrs: ResolveAttrs,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, IdentityError>> + Send + '_>> {
        Box::pin(async move { self.resolve(attrs, Channel::Api) })
    }

    fn resolve_mcp(
        &self,
        attrs: ResolveAttrs,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, IdentityError>> + Send + '_>> {
        Box::pin(async move { self.resolve(attrs, Channel::Mcp) })
    }
}

impl TestResolver {
    fn resolve(&self, attrs: ResolveAttrs, channel: Channel) -> Result<Caller, IdentityError> {
        match self.mode {
            ResolverMode::Missing => Err(IdentityError::NotRegistered),
            ResolverMode::Registered(active) if !active => Err(IdentityError::Inactive),
            ResolverMode::Registered(_active) => Ok(Caller {
                user: test_user(attrs),
                channel,
            }),
        }
    }
}

fn test_user(attrs: ResolveAttrs) -> User {
    let now = Utc::now();
    User {
        id: Uuid::nil(),
        sub: attrs.sub,
        email: attrs.email,
        display_name: attrs.name,
        is_active: true,
        created_at: now,
        updated_at: now,
    }
}

fn state(mode: ResolverMode) -> Result<AppState, Box<dyn std::error::Error>> {
    let mut keys = HashMap::new();
    keys.insert(
        "kid-1".to_owned(),
        DecodingKey::from_rsa_pem(PUB_KEY.as_bytes())?,
    );
    let pool = PgPoolOptions::new().connect_lazy("postgres://opsgate:opsgate@localhost/opsgate")?;
    let config = Arc::new(opsgate_core::Config {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9091),
        database_url: "postgres://opsgate:opsgate@localhost/opsgate".to_owned(),
        db_max_connections: 1,
        authgate_url: "https://auth.example.test".to_owned(),
        opsgate_public_url: "http://localhost:9091".to_owned(),
        oauth_client_id: "client".to_owned(),
        oauth_redirect_url: "http://localhost:9091/callback".to_owned(),
        resource_url: "https://api.example.test".to_owned(),
        jwks_cache_ttl: Duration::from_secs(300),
        secure_cookies: false,
    });
    let jwks = Arc::new(JwksCache::with_keys(
        config.authgate_url.clone(),
        config.resource_url.clone(),
        keys,
    ));
    Ok(AppState::new(
        pool,
        config,
        jwks,
        Arc::new(TestResolver { mode }),
        reqwest::Client::new(),
    ))
}

fn token(
    sub: &str,
    iss: &str,
    aud: Value,
    exp: usize,
    kid: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    let claims = TestClaims {
        sub: sub.to_owned(),
        email: "user@example.test".to_owned(),
        name: "User".to_owned(),
        iss: iss.to_owned(),
        aud,
        exp,
    };
    Ok(encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(KEY.as_bytes())?,
    )?)
}

fn future_exp() -> usize {
    epoch_secs() + 3600
}

fn epoch_secs() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as usize)
        .unwrap_or(0)
}

#[tokio::test]
async fn verify_accepts_valid_token() -> Result<(), Box<dyn std::error::Error>> {
    let state = state(ResolverMode::Registered(true))?;
    let token = token(
        "sub-1",
        "https://auth.example.test",
        json!("https://api.example.test"),
        future_exp(),
        "kid-1",
    )?;
    let caller = verify_bearer(&state, &token, RequestMeta::default()).await?;
    assert_eq!(caller.user.sub, "sub-1");
    Ok(())
}

#[tokio::test]
async fn verify_rejects_invalid_claims_without_panic() -> Result<(), Box<dyn std::error::Error>> {
    let state = state(ResolverMode::Registered(true))?;
    let cases = [
        token(
            "sub-1",
            "https://auth.example.test",
            json!("https://api.example.test"),
            epoch_secs().saturating_sub(3600),
            "kid-1",
        )?,
        token(
            "sub-1",
            "https://other.example.test",
            json!("https://api.example.test"),
            future_exp(),
            "kid-1",
        )?,
        token(
            "sub-1",
            "https://auth.example.test",
            json!("https://other.example.test"),
            future_exp(),
            "kid-1",
        )?,
        token(
            "sub-1",
            "https://auth.example.test",
            json!("https://api.example.test"),
            future_exp(),
            "unknown",
        )?,
        "not-a-jwt".to_owned(),
        alg_none_token(),
    ];
    for (idx, candidate) in cases.into_iter().enumerate() {
        let err = verify_bearer(&state, &candidate, RequestMeta::default())
            .await
            .err();
        assert!(
            matches!(err, Some(AuthError::InvalidToken)),
            "case {idx}: {err:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn verify_accepts_aud_array_and_trailing_slash() -> Result<(), Box<dyn std::error::Error>> {
    let state = state(ResolverMode::Registered(true))?;
    let token = token(
        "sub-1",
        "https://auth.example.test",
        json!(["other", "https://api.example.test/"]),
        future_exp(),
        "kid-1",
    )?;
    let caller = verify_bearer(&state, &token, RequestMeta::default()).await?;
    assert_eq!(caller.user.sub, "sub-1");
    Ok(())
}

#[tokio::test]
async fn verify_maps_registered_state_errors() -> Result<(), Box<dyn std::error::Error>> {
    let valid = token(
        "sub-1",
        "https://auth.example.test",
        json!("https://api.example.test"),
        future_exp(),
        "kid-1",
    )?;
    let missing = state(ResolverMode::Missing)?;
    let missing_err = verify_bearer(&missing, &valid, RequestMeta::default())
        .await
        .err();
    assert!(matches!(missing_err, Some(AuthError::NotRegistered)));

    let inactive = state(ResolverMode::Registered(false))?;
    let inactive_err = verify_bearer(&inactive, &valid, RequestMeta::default())
        .await
        .err();
    assert!(matches!(inactive_err, Some(AuthError::Inactive)));
    Ok(())
}

fn alg_none_token() -> String {
    let header = base64_url_json(&json!({"alg":"none","kid":"kid-1"}));
    let claims = base64_url_json(&json!({
        "sub":"sub-1",
        "email":"user@example.test",
        "name":"User",
        "iss":"https://auth.example.test",
        "aud":"https://api.example.test",
        "exp": future_exp()
    }));
    format!("{header}.{claims}.")
}

fn base64_url_json(value: &Value) -> String {
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        value.to_string().as_bytes(),
    )
}

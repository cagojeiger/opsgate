use secrecy::SecretString;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::http::header::WWW_AUTHENTICATE;
use axum::http::{Method, Request, StatusCode};
use axum::response::Response;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use opsgate_model::{Caller, Channel, IdentityError, ResolveAttrs, User};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt as _;
use uuid::Uuid;

use crate::identity::CallerResolver;
use crate::state::{AppState, AuthState, ToolState};

use crate::auth::api::resolve_api_caller;
use crate::auth::bearer::AuthError;

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

const TEST_DB_URL: &str = "postgres://opsgate:opsgate@localhost/opsgate?connect_timeout=1";

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
            ResolverMode::Registered(_active) => Ok(caller(attrs, channel)),
        }
    }
}

fn caller(attrs: ResolveAttrs, channel: Channel) -> Caller {
    Caller {
        user: test_user(attrs),
        channel,
        request_id: None,
        remote_ip: None,
        user_agent: None,
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

fn attrs() -> ResolveAttrs {
    ResolveAttrs {
        sub: "sub-1".to_owned(),
        email: "user@example.test".to_owned(),
        name: "User".to_owned(),
    }
}

fn state(mode: ResolverMode) -> Result<AppState, Box<dyn std::error::Error>> {
    state_with_resource_url(mode, "https://api.example.test")
}

fn state_with_resource_url(
    mode: ResolverMode,
    resource_url: &str,
) -> Result<AppState, Box<dyn std::error::Error>> {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy(TEST_DB_URL)?;
    let config = Arc::new(crate::config::Config {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9091),
        database_url: TEST_DB_URL.to_owned(),
        database_migrate_url: TEST_DB_URL.to_owned(),
        db_max_connections: 1,
        authgate_url: "https://auth.example.test".to_owned(),
        opsgate_public_url: "http://localhost:9091".to_owned(),
        oauth_client_id: "client".to_owned(),
        oauth_redirect_url: "http://localhost:9091/callback".to_owned(),
        resource_url: resource_url.to_owned(),
        master_key: SecretString::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()),
        signup: crate::config::SignupConfig::default(),
        jwks_cache_ttl: Duration::from_secs(300),
        openapi_enabled: false,
        secure_cookies: false,
    });
    let jwt = crate::auth::jwt::JwtAuthority::from_jwks(&config, aliri_jwks()?);
    let oidc = Arc::new(crate::auth::oidc::OidcProvider::new(
        &config,
        reqwest::Client::new(),
    ));
    let credential_repo = opsgate_db::CredentialRepo::new(pool.clone());
    let cipher = opsgate_service::Cipher::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")?;
    let sealer = opsgate_service::Sealer::new(cipher);
    let credentials = Arc::new(opsgate_service::credential::CredentialService::new(
        credential_repo,
        sealer.clone(),
    ));
    let api_calls = Arc::new(opsgate_service::api_call::ApiCallService::new(
        opsgate_db::CredentialRepo::new(pool.clone()),
        opsgate_db::ApiCallHistoryRepo::new(pool.clone()),
        opsgate_db::AuditRepo::new(pool.clone()),
        sealer.clone(),
    )?);
    let audit_repo = opsgate_db::AuditRepo::new(pool.clone());
    let audit = Arc::new(audit_repo.clone());
    let reads = Arc::new(opsgate_db::ReadRepo::new(pool.clone()));
    let target_pg_pools = opsgate_service::TargetPgPools::new();
    let sql_schema = Arc::new(opsgate_service::sql_schema::SqlSchemaService::new(
        opsgate_db::CredentialRepo::new(pool.clone()),
        audit_repo.clone(),
        sealer.clone(),
        target_pg_pools.clone(),
    ));
    let sql_query = Arc::new(opsgate_service::sql_query::SqlQueryService::new(
        opsgate_db::CredentialRepo::new(pool.clone()),
        opsgate_db::SqlQueryHistoryRepo::new(pool.clone()),
        audit_repo,
        sealer,
        target_pg_pools,
    ));
    Ok(AppState {
        db: pool,
        config,
        auth: AuthState {
            jwt,
            oidc,
            resolver: Arc::new(TestResolver { mode }),
        },
        tools: ToolState {
            credentials,
            api_calls,
            sql_schema,
            sql_query,
        },
        audit,
        reads,
    })
}

fn jwt_authority(
    resource_url: &str,
) -> Result<crate::auth::jwt::JwtAuthority, Box<dyn std::error::Error>> {
    let mut config = test_config(resource_url);
    config.resource_url = resource_url.to_owned();
    Ok(crate::auth::jwt::JwtAuthority::from_jwks(
        &config,
        aliri_jwks()?,
    ))
}

fn test_config(resource_url: &str) -> crate::config::Config {
    crate::config::Config {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9091),
        database_url: TEST_DB_URL.to_owned(),
        database_migrate_url: TEST_DB_URL.to_owned(),
        db_max_connections: 1,
        authgate_url: "https://auth.example.test".to_owned(),
        opsgate_public_url: "http://localhost:9091".to_owned(),
        oauth_client_id: "client".to_owned(),
        oauth_redirect_url: "http://localhost:9091/callback".to_owned(),
        resource_url: resource_url.to_owned(),
        master_key: SecretString::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()),
        signup: crate::config::SignupConfig::default(),
        jwks_cache_ttl: Duration::from_secs(300),
        openapi_enabled: false,
        secure_cookies: false,
    }
}

fn aliri_jwks() -> Result<aliri::Jwks, Box<dyn std::error::Error>> {
    use base64::Engine as _;

    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(
        "sfE1HSV9Fnl00COG8SPEtPGOMa95P4XMhpsnSV4lbfoUFyuAjPUc_uFtkmH2s3VoNKdYdHsi_PNycvS5sX0LOOE9Zon7OwmZZvIocZmY97p7BUAAO4XfXxh8MDW1UKzBswG-7TVekRKAbPNNKUjJegbWtFYErU_7WlF8CrCX5ebDfyjkuGUH-bYRRnRd10pX_PTIQ6159FdJ6R9wgNIk0gRNRHsWEdlV-AxhPAmYXPWFNvYpDtiNlCi3anCp8kTlWzLKKeJdWBHzr3xuByUGXLcfCIoVsBd-SXtpS62E2pkt8D8OitcxcE9_8DZcXB7Z-TIj544uAY3XaPTmeKPcdw",
    )?;
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode("AQAB")?;
    let rsa = aliri::jwa::Rsa::from_public_components(n, e)?;
    let key = aliri::Jwk::from(rsa)
        .with_algorithm(aliri::jwa::Algorithm::RS256)
        .with_key_id(aliri::jwk::KeyId::from_static("kid-1"));
    let mut jwks = aliri::Jwks::default();
    jwks.add_key(key);
    Ok(jwks)
}

fn registered_state() -> Result<AppState, Box<dyn std::error::Error>> {
    state(ResolverMode::Registered(true))
}

async fn request(
    state: AppState,
    request: Request<Body>,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(crate::routes::app(state).oneshot(request).await?)
}

fn valid_api_token() -> Result<String, Box<dyn std::error::Error>> {
    token(
        "sub-1",
        "https://auth.example.test",
        json!("https://api.example.test"),
        future_exp(),
        "kid-1",
    )
}

fn authed_json_request(
    method: Method,
    uri: &str,
    body: &str,
) -> Result<Request<Body>, Box<dyn std::error::Error>> {
    let valid = valid_api_token()?;
    Ok(Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {valid}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))?)
}

async fn response_json(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    Ok(serde_json::from_slice(&body)?)
}

fn json_array_contains(value: &Value, field: &str, expected: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(expected)))
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

mod jwt;
mod routes;

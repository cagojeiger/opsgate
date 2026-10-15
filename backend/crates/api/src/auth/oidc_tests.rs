#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result
)]

use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use openidconnect::core::{CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
use openidconnect::{AccessToken, AccessTokenHash, JsonWebKeyId, PrivateSigningKey};
use serde_json::{Value, json};
use tokio::sync::{Barrier, Notify, Semaphore};

use super::*;
use crate::auth::oauth_exchange::exchange_code_for_userinfo;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const CLIENT_ID: &str = "browser-test";
const NONCE: &str = "browser-nonce";
const ACCESS_TOKEN: &str = "test-access-token";

// Generated test-only RSA keys; never used outside this local mock provider.
const KEY_A: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAkv2mN1UzsYjiA938gjZ+k+W48yPmfr5EG+vG2q7G7KS0Ebgg
S8VvCP37jhCCvQDDXDVYw4eRaNIeK4voAHr5oa6PWWtJFT2CS7hAR/xmi1gl64jb
SClt6GAJt3HHemnWgOPd8nK32T8DYmVvzFNLK5hd1c/OQuPGsFqHevZA4oyoDU5P
BhS9J/OFl9r89/wgCtcxzL53NNDQN/uv2MbO+40LnMCjf9UVyUpwKRXgyVtuaIn0
nvgdH04vFMotA4qre9Z2FEXNB0mJenhA5q0S76SrmU2nZo7O+GDxmxwpx4JOxGfN
7EEwLsoR9qBNGssB0P6c+U0c2/cDg4RLEhAryQIDAQABAoIBAAjH9qSuVjncRK1I
twej4ASvl/CNg9ztOqYk3BKvF4LmVXwMAQDpzOfvfVZHsfm+yIzzAmge6o7Fo6gE
EgJqVkykgBuOS1XFoImruopaX5liNRS4rqnlULOtvhLbjRhI55e4VSdhV06XAzme
9/JvxOk4L13hLdAk6ZcaN2b+/FIUUBxBQFiNAG4xO1y2iRS5zFS62iPIPThVj1gh
87HVu9LhgTnZk0qzYU+J8rY/3/+UpUdGNPAKhg5JKUcvyprCUoSL+x5lVcF0LyYJ
C9vOZMLsNPdxyq2UtAie1bhQLAo+02m+QkfI1Kgj6AaOZMy9XWyK/Y77bXwea+a9
YYm1PXECgYEAxqMUOWOcwF0nhw+AE7ZcE6wCEFW8ho0OxdSCiGX1bbxXkEkbb15H
7SaQ0sHyWcfyJWe/8WoonQFP9uHD6WS5FxNx1GH/cKcnpHNOnYmQO2CjixS8c3DL
R1xOL4mbtI00c5l+pVW0YOGrb+DP6uPBD90p2tP4m2l7m/WmL4wW+7kCgYEAvXBy
nyhJMAj6VYST2Co7iTOPAMdaJcceEeVBkdkKHATFnPpjW34asGjn1/5TQI2utAG2
s4HfRupldk2Ep8Y4KaWWcBd7NWCmuPeOFIa9Y2bTba50mrM/fRgD/a8RbF1vItot
wbCfytUQbufX/o5JoUU4Mqel7ngzjwmiwBCkWJECgYBgqjoMV5qPzoWO548niKY0
eI+kjWSqgfi/c1R2tk+CsJZYRAuS3enY0dzGg9XBtVj0tRGmlUfgaCQW+/VQHlEo
lrDdbzdVBjN3hxmp9qj3DGdqJpQzBaAXQSdXYPsiGVl+LCOCqDuYrhm0302vfFiW
tMVKlb81OlcKJbhTCTSiGQKBgDK6AqdltTtcnBP8PU6b+HdDzB4sQ5JsIDwwhH9W
e+OGz5e6YJKmUOU+Ih7vZkGZ7tcawl6M/0nRCDxGg6gdZvqX8ZGwZ/iiGeLbvzr1
3Y7ZgPIUzfqC1xRbMu5iS6sV1eWiQLBl6FP6+7yG7oqmdUbu7x55T/BsVXoO3XrK
ugdRAoGBAIqGHl3kw7MSVaGapYfHD90EGfvj89X6hyZ/0yL8XR4kY6Fu+JcTqk2N
rYqEDAF0xawu8EasyVJvGiVx+1VnXerTT0AP/11SAsMf92hexeFXsItPKwS+ACFB
S3YqOuuE84NkyRADAP5MfUdZDtBS0NY7ZSzmiBenBxUdoMUwN57W
-----END RSA PRIVATE KEY-----
"#;
const KEY_B: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAweHeX1fRzJEAkPHO++r10Mtn1qnyCRSuM1hVd3tgVFBv1EQT
FWYI0BT7YpLwJ2sKFT4TvCB+r7wMqTEOUksYmzytPmMST538bTUFJL0NLpqT3tE5
ybzOPdA7I1F+56gFAUCYfldFTfqrXVpt1M8Oisdn7MfH6vEt0IfpCh/BmjNfhWl6
/yMudwkzxxU1o4HOtTOEZ14hhCTGJO0GwMEoq7nRqba/P3r7mwr5+O4uj8hYfccl
acix1GzjPUY4wdPIygj8a+uBkV0p1w94s4Tn7IyfePma0LF6L5IapgUkq71DkjR3
FwEq2vPkniAL7Zlae3QfITs/nTGdGICZL32cYwIDAQABAoIBAA6IcENEUXEck2bK
AWJnx9pJTPTN01sz5iTqI6nroRpg1ykZmzaY6eMzF27Zpc/GmcBi4VbSNrzUgzxx
dWncwDDuuOu6wGYgaQoEleidlS3fn2Lt2v+QvALtJ2mr06/oq8tevK+HuiWwuwSp
4R65EJV9ggBBL26genctoN3F6Jy2yHsHqgKM2jjRkMMRo2wwO754PNgwgXiJFBpq
mkzHKo/oj4P0sWKSGiNLTg6y0+dQNgP9e/qESlhpLCNJcsat8ijXQudqz4CTRRbT
a3fcshfHYVA3le2BUDbklslLacllMiIa0t1hlPdpkF/yCEwsT/+REbCAj4oPj01R
l2idOGECgYEA+mLh6VTEsPAWmHUi3nrVr+mvtsKQ1fFKQEl7hrfqxF10EQ4a53S2
9o2q4U9nDDVV9yegZMI6pIrodwXTeQY2X3PJ/LDnVOJ5mT20jgjDZI8I9l2e0iJA
/uBgKg70iLR/AaYTTuoA93Pg3R819B0DmtDYBl7PzzZ5Yo51pUMaOGECgYEAxjqt
CRGi2Ngs3Rq9PSNSnxwvZEBJKC/+oRYBqBa6ISEpxbAanRL+WSPqsiG65vA16cf9
be09mSUrEwDHPsZxTp1Ut4UlvSS51zSso5JVOhI2w7simYPt9LGDuF4LQ3avFBMB
3YPFHSAEoaR3Rxh+ZMNwBdAjXbZ4yh0vu2Wyu0MCgYEAw0Vw2E9C4pcrmBTqb8Yu
dvXyEr9kw2VdugtU6fjvf9s+VLrCYrZUpq5PkU4imJPUCl/+J/aOU5r9ty11ApLE
vuaHpam1kC7cFJXaBVdyQy+GFtVmso0CUYRdmw90yFS0JG4H6uh2foYB3ZGku1AR
aqDriPRSb1EVk7Z0q8FMZqECgYAB4/Ncf8eOy9j5rtSZLaoPDGTDTv2jnXmPLbeM
U9Mol7lfQkOutcypKveFBV9T7nyFIzwefUG2IS2c+8fqqFfSSRvSuDlY6W3ASKdQ
1AduC1hsW2+ECUcOq1a3PmZbGVmoFlpRM32AvppstDXS/r/N1DNQSuDbdu8F9mtL
HTgsIwKBgQDAwY++ZW10EHkhDyXV8l38NoKa3yKt889zBPNiWOpb2GLkUK3hIZ1C
cfvVswZh/8dsadM1XfwQ0KakEGsXrnl+JNTTeBxf6lJlnJJHQhD4VeLBnltDDDcJ
LHO7AGFy72uy7UPGqoulqwpUurPxtC8QwDnH1WcQGeUXk4lPz9tpTw==
-----END RSA PRIVATE KEY-----
"#;

struct Gate {
    started: Notify,
    release: Semaphore,
}

impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Notify::new(),
            release: Semaphore::new(0),
        })
    }

    async fn wait(&self) {
        self.started.notify_one();
        let permit = self.release.acquire().await.expect("open test gate");
        permit.forget();
    }
}

struct Responses {
    jwks: Value,
    token: String,
    userinfo_sub: String,
    discovery_status: StatusCode,
    jwks_status: StatusCode,
    discovery_gate: Option<Arc<Gate>>,
    jwks_gate: Option<Arc<Gate>>,
    token_barrier: Option<Arc<Barrier>>,
}

#[derive(Clone)]
struct Mock {
    issuer: String,
    responses: Arc<RwLock<Responses>>,
    discovery_calls: Arc<AtomicUsize>,
    jwks_calls: Arc<AtomicUsize>,
    token_calls: Arc<AtomicUsize>,
    userinfo_calls: Arc<AtomicUsize>,
}

struct Fixture {
    provider: Arc<OidcProvider>,
    mock: Mock,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn verification_key(pem: &str, kid: &str) -> TestResult<openidconnect::core::CoreJsonWebKey> {
    let key = CoreRsaPrivateSigningKey::from_pem(pem, Some(JsonWebKeyId::new(kid.to_owned())))
        .map_err(std::io::Error::other)?;
    Ok(key.as_verification_key())
}

fn jwks(pem: &str, kid: &str) -> TestResult<Value> {
    Ok(serde_json::to_value(CoreJsonWebKeySet::new(vec![
        verification_key(pem, kid)?,
    ]))?)
}

fn id_token(issuer: &str, pem: &str, kid: &str, overrides: Value) -> TestResult<String> {
    let now = chrono::Utc::now().timestamp();
    let hash = AccessTokenHash::from_token(
        &AccessToken::new(ACCESS_TOKEN.to_owned()),
        &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        &verification_key(pem, kid)?,
    )?;
    let mut claims = json!({
        "iss": issuer, "aud": CLIENT_ID, "sub": "user-1", "iat": now,
        "exp": now + 300, "nonce": NONCE, "at_hash": hash,
    });
    for (key, value) in overrides.as_object().expect("claim overrides") {
        claims[key] = value.clone();
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    Ok(encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes())?,
    )?)
}

async fn discovery(State(mock): State<Mock>) -> Response {
    mock.discovery_calls.fetch_add(1, Ordering::SeqCst);
    let (status, gate) = {
        let responses = mock.responses.read().await;
        (responses.discovery_status, responses.discovery_gate.clone())
    };
    if let Some(gate) = gate {
        gate.wait().await;
    }
    if status != StatusCode::OK {
        return (status, "upstream-private-body").into_response();
    }
    Json(json!({
        "issuer": mock.issuer,
        "authorization_endpoint": format!("{}/authorize", mock.issuer),
        "token_endpoint": format!("{}/token", mock.issuer),
        "userinfo_endpoint": format!("{}/userinfo", mock.issuer),
        "jwks_uri": format!("{}/keys", mock.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
    .into_response()
}

async fn keys(State(mock): State<Mock>) -> Response {
    mock.jwks_calls.fetch_add(1, Ordering::SeqCst);
    let (status, jwks, gate) = {
        let responses = mock.responses.read().await;
        (
            responses.jwks_status,
            responses.jwks.clone(),
            responses.jwks_gate.clone(),
        )
    };
    if let Some(gate) = gate {
        gate.wait().await;
    }
    if status != StatusCode::OK {
        return (status, "upstream-private-body").into_response();
    }
    Json(jwks).into_response()
}

async fn token(State(mock): State<Mock>) -> Json<Value> {
    mock.token_calls.fetch_add(1, Ordering::SeqCst);
    let (token, barrier) = {
        let responses = mock.responses.read().await;
        (responses.token.clone(), responses.token_barrier.clone())
    };
    if let Some(barrier) = barrier {
        barrier.wait().await;
    }
    Json(json!({"access_token": ACCESS_TOKEN, "token_type": "Bearer", "id_token": token}))
}

async fn userinfo(State(mock): State<Mock>) -> Json<Value> {
    mock.userinfo_calls.fetch_add(1, Ordering::SeqCst);
    Json(json!({"sub": mock.responses.read().await.userinfo_sub, "email": "test@example.test"}))
}

async fn fixture() -> TestResult<Fixture> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let issuer = format!("http://{}", listener.local_addr()?);
    let mock = Mock {
        responses: Arc::new(RwLock::new(Responses {
            jwks: jwks(KEY_A, "key-a")?,
            token: id_token(&issuer, KEY_A, "key-a", json!({}))?,
            userinfo_sub: "user-1".to_owned(),
            discovery_status: StatusCode::OK,
            jwks_status: StatusCode::OK,
            discovery_gate: None,
            jwks_gate: None,
            token_barrier: None,
        })),
        issuer: issuer.clone(),
        discovery_calls: Arc::new(AtomicUsize::new(0)),
        jwks_calls: Arc::new(AtomicUsize::new(0)),
        token_calls: Arc::new(AtomicUsize::new(0)),
        userinfo_calls: Arc::new(AtomicUsize::new(0)),
    };
    let router = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/keys", get(keys))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .with_state(mock.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("mock OIDC server");
    });
    let provider = Arc::new(OidcProvider {
        issuer,
        client_id: CLIENT_ID.to_owned(),
        redirect_url: "http://localhost/callback".to_owned(),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        cache: RwLock::new(MetadataCache::default()),
        refresh: Mutex::new(()),
    });
    Ok(Fixture {
        provider,
        mock,
        server,
    })
}

async fn exchange(
    provider: &OidcProvider,
) -> opsgate_core::Result<super::super::oauth_exchange::UserInfo> {
    exchange_code_for_userinfo(provider, "one-use-code", "pkce-verifier", NONCE).await
}

fn calls(counter: &AtomicUsize) -> usize {
    counter.load(Ordering::SeqCst)
}

async fn expire(provider: &OidcProvider) {
    provider
        .cache
        .write()
        .await
        .cached
        .as_mut()
        .expect("warm cache")
        .fetched_at = Instant::now() - METADATA_CACHE_TTL - Duration::from_secs(1);
}

#[tokio::test]
async fn valid_browser_token_reuses_snapshot_without_extra_io() -> TestResult {
    let f = fixture().await?;
    for _ in 0..2 {
        assert_eq!(exchange(&f.provider).await?.sub, "user-1");
    }
    assert_eq!(calls(&f.mock.discovery_calls), 1);
    assert_eq!(calls(&f.mock.jwks_calls), 1);
    assert_eq!(calls(&f.mock.token_calls), 2);
    assert_eq!(calls(&f.mock.userinfo_calls), 2);
    Ok(())
}

#[tokio::test]
async fn unknown_and_reused_kid_refresh_once_without_reexchanging_code() -> TestResult {
    for kid in ["key-b", "key-a"] {
        let f = fixture().await?;
        f.provider.client().await?;
        let fetched_at = f
            .provider
            .cache
            .read()
            .await
            .cached
            .as_ref()
            .expect("cache")
            .fetched_at;
        {
            let mut responses = f.mock.responses.write().await;
            responses.jwks = jwks(KEY_B, kid)?;
            responses.token = id_token(&f.mock.issuer, KEY_B, kid, json!({}))?;
        }
        assert_eq!(exchange(&f.provider).await?.sub, "user-1");
        assert_eq!(calls(&f.mock.discovery_calls), 1);
        assert_eq!(calls(&f.mock.jwks_calls), 2);
        assert_eq!(calls(&f.mock.token_calls), 1);
        assert_eq!(calls(&f.mock.userinfo_calls), 1);
        assert_eq!(
            f.provider
                .cache
                .read()
                .await
                .cached
                .as_ref()
                .expect("cache")
                .fetched_at,
            fetched_at
        );
    }
    Ok(())
}

#[tokio::test]
async fn retry_failure_is_bounded_and_does_not_call_userinfo() -> TestResult {
    let f = fixture().await?;
    f.provider.client().await?;
    // The provider still publishes A while the token requires B.
    f.mock.responses.write().await.token = id_token(&f.mock.issuer, KEY_B, "key-b", json!({}))?;
    assert!(exchange(&f.provider).await.is_err());
    assert_eq!(calls(&f.mock.jwks_calls), 2);
    assert_eq!(calls(&f.mock.token_calls), 1);
    assert_eq!(calls(&f.mock.userinfo_calls), 0);
    Ok(())
}

#[tokio::test]
async fn failed_refresh_preserves_good_keys_and_does_not_expose_response_body() -> TestResult {
    let f = fixture().await?;
    f.provider.client().await?;
    {
        let mut responses = f.mock.responses.write().await;
        responses.token = id_token(&f.mock.issuer, KEY_B, "key-b", json!({}))?;
        responses.jwks_status = StatusCode::SERVICE_UNAVAILABLE;
    }
    let error = exchange(&f.provider)
        .await
        .expect_err("new key unavailable");
    assert!(!error.to_string().contains("upstream-private-body"));
    f.mock.responses.write().await.token = id_token(&f.mock.issuer, KEY_A, "key-a", json!({}))?;
    assert_eq!(exchange(&f.provider).await?.sub, "user-1");
    assert_eq!(calls(&f.mock.jwks_calls), 2);
    assert_eq!(calls(&f.mock.token_calls), 2);
    Ok(())
}

#[tokio::test]
async fn invalid_claims_do_not_refresh_and_subject_mismatch_is_rejected() -> TestResult {
    let f = fixture().await?;
    f.provider.client().await?;
    for claims in [
        json!({"iss": "https://other.example.test"}),
        json!({"aud": "other-client"}),
        json!({"nonce": "wrong-nonce"}),
        json!({"exp": 1}),
        json!({"at_hash": "wrong-hash"}),
    ] {
        f.mock.responses.write().await.token = id_token(&f.mock.issuer, KEY_A, "key-a", claims)?;
        assert!(exchange(&f.provider).await.is_err());
    }
    assert_eq!(calls(&f.mock.jwks_calls), 1);
    assert_eq!(calls(&f.mock.userinfo_calls), 0);
    {
        let mut responses = f.mock.responses.write().await;
        responses.token = id_token(&f.mock.issuer, KEY_A, "key-a", json!({}))?;
        responses.userinfo_sub = "other-user".to_owned();
    }
    assert!(exchange(&f.provider).await.is_err());
    assert_eq!(calls(&f.mock.userinfo_calls), 1);
    assert_eq!(calls(&f.mock.jwks_calls), 1);
    Ok(())
}

#[tokio::test]
async fn disallowed_algorithm_and_ambiguous_keys_do_not_refresh() -> TestResult {
    let f = fixture().await?;
    let now = chrono::Utc::now().timestamp();
    f.mock.responses.write().await.token = encode(
        &Header::new(Algorithm::HS256),
        &json!({"iss": f.mock.issuer, "aud": CLIENT_ID, "sub": "user-1",
            "iat": now, "exp": now + 300, "nonce": NONCE}),
        &EncodingKey::from_secret(b"untrusted-shared-secret"),
    )?;
    assert!(exchange(&f.provider).await.is_err());
    assert_eq!(calls(&f.mock.jwks_calls), 1);
    assert_eq!(calls(&f.mock.token_calls), 1);

    let ambiguous = fixture().await?;
    ambiguous.mock.responses.write().await.jwks = json!({"keys": [
        verification_key(KEY_A, "key-a")?, verification_key(KEY_B, "key-a")?,
    ]});
    assert!(exchange(&ambiguous.provider).await.is_err());
    assert_eq!(calls(&ambiguous.mock.jwks_calls), 1);
    assert_eq!(calls(&ambiguous.mock.token_calls), 1);
    Ok(())
}

#[tokio::test]
async fn refreshed_token_still_checks_nonce_and_access_token_hash() -> TestResult {
    for claims in [
        json!({"nonce": "wrong-nonce"}),
        json!({"at_hash": "wrong-hash"}),
    ] {
        let f = fixture().await?;
        f.provider.client().await?;
        {
            let mut responses = f.mock.responses.write().await;
            responses.jwks = jwks(KEY_B, "key-b")?;
            responses.token = id_token(&f.mock.issuer, KEY_B, "key-b", claims)?;
        }
        assert!(exchange(&f.provider).await.is_err());
        assert_eq!(calls(&f.mock.jwks_calls), 2);
        assert_eq!(calls(&f.mock.token_calls), 1);
        assert_eq!(calls(&f.mock.userinfo_calls), 0);
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_callbacks_share_successful_and_failed_refresh_attempts() -> TestResult {
    for status in [StatusCode::OK, StatusCode::SERVICE_UNAVAILABLE] {
        let f = fixture().await?;
        f.provider.client().await?;
        let gate = Gate::new();
        let count = 4;
        {
            let mut responses = f.mock.responses.write().await;
            responses.jwks = jwks(KEY_B, "key-b")?;
            responses.token = id_token(&f.mock.issuer, KEY_B, "key-b", json!({}))?;
            responses.jwks_status = status;
            responses.jwks_gate = Some(gate.clone());
            // Every callback captures its snapshot before any token response.
            responses.token_barrier = Some(Arc::new(Barrier::new(count)));
        }
        let mut tasks = Vec::new();
        for _ in 0..count {
            let provider = f.provider.clone();
            tasks.push(tokio::spawn(async move { exchange(&provider).await }));
        }
        tokio::time::timeout(Duration::from_secs(5), gate.started.notified()).await?;
        gate.release.add_permits(1);
        for task in tasks {
            let result = tokio::time::timeout(Duration::from_secs(5), task).await??;
            assert_eq!(result.is_ok(), status == StatusCode::OK);
        }
        assert_eq!(calls(&f.mock.jwks_calls), 2);
        assert_eq!(calls(&f.mock.token_calls), count);
        assert_eq!(calls(&f.mock.discovery_calls), 1);
    }
    Ok(())
}

#[tokio::test]
async fn discovery_failure_keeps_stale_cache_and_cold_failure_is_shared() -> TestResult {
    let f = fixture().await?;
    f.provider.client().await?;
    expire(&f.provider).await;
    f.mock.responses.write().await.discovery_status = StatusCode::SERVICE_UNAVAILABLE;
    assert_eq!(exchange(&f.provider).await?.sub, "user-1");
    assert_eq!(calls(&f.mock.discovery_calls), 2);
    assert_eq!(calls(&f.mock.jwks_calls), 1);

    let cold = fixture().await?;
    let gate = Gate::new();
    {
        let mut responses = cold.mock.responses.write().await;
        responses.discovery_status = StatusCode::SERVICE_UNAVAILABLE;
        responses.discovery_gate = Some(gate.clone());
    }
    // Hold the shared gate so both readers observe the same cold-cache epoch.
    let refresh = cold.provider.refresh.lock().await;
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let provider = cold.provider.clone();
        let mut attempt = Box::pin(async move { provider.client().await });
        // With the cache unlocked, the first pending await is the refresh gate.
        poll_fn(|cx| {
            assert!(attempt.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        tasks.push(tokio::spawn(attempt));
    }
    drop(refresh);
    tokio::time::timeout(Duration::from_secs(5), gate.started.notified()).await?;
    gate.release.add_permits(1);
    for task in tasks {
        assert!(
            tokio::time::timeout(Duration::from_secs(5), task)
                .await??
                .is_err()
        );
    }
    assert_eq!(calls(&cold.mock.discovery_calls), 1);
    Ok(())
}

#[tokio::test]
async fn ttl_discovery_and_key_refresh_share_gate_without_extending_ttl() -> TestResult {
    for discovery_first in [true, false] {
        let f = fixture().await?;
        let (_, mut observed) = f.provider.client_with_snapshot().await?;
        expire(&f.provider).await;
        observed.cached.fetched_at = f
            .provider
            .cache
            .read()
            .await
            .cached
            .as_ref()
            .expect("cache")
            .fetched_at;
        let gate = Gate::new();
        {
            let mut responses = f.mock.responses.write().await;
            responses.jwks = jwks(KEY_B, "key-b")?;
            if discovery_first {
                responses.discovery_gate = Some(gate.clone());
            } else {
                responses.jwks_gate = Some(gate.clone());
            }
        }
        if discovery_first {
            let provider = f.provider.clone();
            let discovery = tokio::spawn(async move { provider.client().await });
            tokio::time::timeout(Duration::from_secs(5), gate.started.notified()).await?;
            let provider = f.provider.clone();
            let forced = tokio::spawn(async move { provider.refresh_jwks(&observed).await });
            gate.release.add_permits(1);
            tokio::time::timeout(Duration::from_secs(5), discovery).await???;
            tokio::time::timeout(Duration::from_secs(5), forced).await???;
            assert_eq!(calls(&f.mock.discovery_calls), 2);
            assert_eq!(calls(&f.mock.jwks_calls), 2);
        } else {
            let provider = f.provider.clone();
            let forced = tokio::spawn(async move { provider.refresh_jwks(&observed).await });
            tokio::time::timeout(Duration::from_secs(5), gate.started.notified()).await?;
            let provider = f.provider.clone();
            let mut attempt = Box::pin(async move { provider.client().await });
            poll_fn(|cx| {
                assert!(attempt.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            let discovery = tokio::spawn(attempt);
            gate.release.add_permits(1);
            tokio::time::timeout(Duration::from_secs(5), forced).await???;
            tokio::time::timeout(Duration::from_secs(5), discovery).await???;
            assert_eq!(calls(&f.mock.discovery_calls), 1);
            assert_eq!(calls(&f.mock.jwks_calls), 2);
            f.mock.responses.write().await.jwks_gate = None;
            // The key fetch retained the old discovery age, so the next reader
            // must discover again instead of treating endpoint metadata as fresh.
            f.provider.client().await?;
            assert_eq!(calls(&f.mock.discovery_calls), 2);
            assert_eq!(calls(&f.mock.jwks_calls), 3);
        }
    }
    Ok(())
}

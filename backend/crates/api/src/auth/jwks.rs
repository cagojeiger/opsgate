use std::collections::HashMap;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    pub aud: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum JwksError {
    #[error("invalid token")]
    InvalidToken,
    #[error("jwks fetch failed")]
    FetchFailed,
}

pub struct JwksCache {
    jwks_url: String,
    issuer: String,
    audience: String,
    ttl: Duration,
    http: reqwest::Client,
    cache: RwLock<Option<CachedKeys>>,
}

#[derive(Clone)]
struct CachedKeys {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Instant,
}

#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

impl JwksCache {
    pub fn new(
        jwks_url: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        ttl: Duration,
        http: reqwest::Client,
    ) -> Self {
        Self {
            jwks_url: jwks_url.into(),
            issuer: issuer.into(),
            audience: audience.into(),
            ttl,
            http,
            cache: RwLock::new(None),
        }
    }

    #[cfg(test)]
    pub fn with_keys(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        keys: HashMap<String, DecodingKey>,
    ) -> Self {
        Self {
            jwks_url: "http://127.0.0.1/unused".to_owned(),
            issuer: issuer.into(),
            audience: audience.into(),
            ttl: Duration::from_secs(300),
            http: reqwest::Client::new(),
            cache: RwLock::new(Some(CachedKeys {
                keys,
                fetched_at: Instant::now(),
            })),
        }
    }

    pub async fn verify(&self, token: &str) -> Result<Claims, JwksError> {
        let header = decode_header(token).map_err(|_error| JwksError::InvalidToken)?;
        if header.alg != Algorithm::RS256 {
            return Err(JwksError::InvalidToken);
        }
        let kid = header.kid.ok_or(JwksError::InvalidToken)?;
        let key = self.key_for_kid(&kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.validate_aud = false;

        let token_data: TokenData<Claims> =
            decode(token, &key, &validation).map_err(|_error| JwksError::InvalidToken)?;
        if !aud_matches(&token_data.claims.aud, &self.audience) {
            return Err(JwksError::InvalidToken);
        }
        Ok(token_data.claims)
    }

    async fn key_for_kid(&self, kid: &str) -> Result<DecodingKey, JwksError> {
        let snapshot = { self.cache.read().await.clone() };
        if let Some(cache) = snapshot {
            let fresh = cache.fetched_at.elapsed() <= self.ttl;
            if fresh && let Some(key) = cache.keys.get(kid) {
                return Ok(key.clone());
            }
        }

        match self.refresh().await {
            Ok(cache) => cache.keys.get(kid).cloned().ok_or(JwksError::InvalidToken),
            Err(error) => {
                let snapshot = { self.cache.read().await.clone() };
                if let Some(cache) = snapshot {
                    if let Some(key) = cache.keys.get(kid) {
                        return Ok(key.clone());
                    }
                    return Err(JwksError::InvalidToken);
                }
                Err(error)
            }
        }
    }

    async fn refresh(&self) -> Result<CachedKeys, JwksError> {
        let response = self
            .http
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|_error| JwksError::FetchFailed)?;
        if !response.status().is_success() {
            return Err(JwksError::FetchFailed);
        }
        let document = response
            .json::<JwksDocument>()
            .await
            .map_err(|_error| JwksError::FetchFailed)?;
        let keys = parse_keys(document)?;
        let cache = CachedKeys {
            keys,
            fetched_at: Instant::now(),
        };
        {
            let mut guard = self.cache.write().await;
            *guard = Some(cache.clone());
        }
        Ok(cache)
    }
}

fn parse_keys(document: JwksDocument) -> Result<HashMap<String, DecodingKey>, JwksError> {
    let mut keys = HashMap::new();
    for jwk in document.keys {
        let is_rsa = jwk.kty.as_deref() == Some("RSA");
        let (Some(kid), Some(n), Some(e)) = (jwk.kid, jwk.n, jwk.e) else {
            continue;
        };
        if !is_rsa {
            continue;
        }
        let key =
            DecodingKey::from_rsa_components(&n, &e).map_err(|_error| JwksError::FetchFailed)?;
        keys.insert(kid, key);
    }
    Ok(keys)
}

pub fn normalize_aud(value: &str) -> &str {
    value.strip_suffix('/').unwrap_or(value)
}

fn aud_matches(aud: &Value, expected: &str) -> bool {
    let expected = normalize_aud(expected);
    match aud {
        Value::String(value) => normalize_aud(value) == expected,
        Value::Array(values) => values.iter().any(|value| {
            value
                .as_str()
                .map(|aud| normalize_aud(aud) == expected)
                .unwrap_or(false)
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{aud_matches, normalize_aud};

    #[test]
    fn normalizes_one_trailing_slash() {
        assert_eq!(normalize_aud("https://api.example/"), "https://api.example");
        assert_eq!(
            normalize_aud("https://api.example//"),
            "https://api.example/"
        );
    }

    #[test]
    fn aud_accepts_string_or_array() {
        assert!(aud_matches(
            &json!("https://api.example/"),
            "https://api.example"
        ));
        assert!(aud_matches(
            &json!(["other", "https://api.example"]),
            "https://api.example/"
        ));
        assert!(!aud_matches(&json!(["other"]), "https://api.example"));
    }
}

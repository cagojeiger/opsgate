use crate::crypto::Sealer;
use opsgate_core::{Error, Result};
use opsgate_model::credential::{CredentialSecret, SecretHeader};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

const SECRET_DOMAIN: &str = "credentials";
const CLIENT_KEY_DOMAIN: &str = "credentials.client_key";

#[derive(Debug, Deserialize)]
pub struct SqlSecret {
    pub(crate) username: SecretString,
    pub(crate) password: SecretString,
}

pub fn seal(sealer: &Sealer, alias: &str, secret: &CredentialSecret) -> Result<Vec<u8>> {
    let plaintext = secret_json(secret)?;
    sealer.seal(SECRET_DOMAIN, alias, &plaintext)
}

pub fn seal_client_key(sealer: &Sealer, alias: &str, key_pem: &str) -> Result<Vec<u8>> {
    sealer.seal(CLIENT_KEY_DOMAIN, alias, key_pem.as_bytes())
}

pub fn open_client_key(sealer: &Sealer, alias: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
    sealer.open(CLIENT_KEY_DOMAIN, alias, ciphertext)
}

pub(crate) fn client_identity_pem(client_cert: &[u8], client_key: &[u8]) -> Vec<u8> {
    let mut identity = client_cert.to_vec();
    if !identity.ends_with(b"\n") {
        identity.push(b'\n');
    }
    identity.extend_from_slice(client_key);
    identity
}

pub fn open_http_headers(
    sealer: &Sealer,
    alias: &str,
    ciphertext: &[u8],
) -> Result<Vec<SecretHeader>> {
    let secret = open_http_secret(sealer, alias, ciphertext)?;
    Ok(secret
        .headers
        .into_iter()
        .map(|header| SecretHeader {
            name: header.name,
            value: header.value,
        })
        .collect())
}

pub fn open_http_header_names(
    sealer: &Sealer,
    alias: &str,
    ciphertext: &[u8],
) -> Result<Vec<String>> {
    let secret = open_http_secret(sealer, alias, ciphertext)?;
    Ok(secret
        .headers
        .into_iter()
        .map(|header| header.name)
        .collect())
}

pub fn open_sql(sealer: &Sealer, alias: &str, ciphertext: &[u8]) -> Result<SqlSecret> {
    let plaintext = sealer.open(SECRET_DOMAIN, alias, ciphertext)?;
    serde_json::from_slice::<SqlSecret>(&plaintext)
        .map_err(|error| Error::internal(format!("decode sql credential secret: {error}")))
}

fn secret_json(secret: &CredentialSecret) -> Result<Vec<u8>> {
    let value = match secret {
        CredentialSecret::Http { headers } => serde_json::json!({
            "headers": headers.iter().map(secret_header_json).collect::<Vec<_>>()
        }),
        CredentialSecret::Sql { username, password } => serde_json::json!({
            "username": username.expose_secret(),
            "password": password.expose_secret(),
        }),
    };
    serde_json::to_vec(&value)
        .map_err(|error| Error::internal(format!("serialize credential secret: {error}")))
}

fn open_http_secret(sealer: &Sealer, alias: &str, ciphertext: &[u8]) -> Result<StoredHttpSecret> {
    let plaintext = sealer.open(SECRET_DOMAIN, alias, ciphertext)?;
    serde_json::from_slice::<StoredHttpSecret>(&plaintext)
        .map_err(|error| Error::internal(format!("decode credential secret: {error}")))
}

fn secret_header_json(header: &SecretHeader) -> serde_json::Value {
    serde_json::json!({
        "name": header.name,
        "value": header.value.expose_secret(),
    })
}

#[derive(Deserialize)]
struct StoredHttpSecret {
    headers: Vec<StoredSecretHeader>,
}

#[derive(Deserialize)]
struct StoredSecretHeader {
    name: String,
    value: SecretString,
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;

    fn sealer() -> Result<Sealer> {
        let key = base64::engine::general_purpose::STANDARD.encode([12_u8; 32]);
        let cipher = crate::crypto::Cipher::new(&key)?;
        Ok(Sealer::new(cipher))
    }

    #[test]
    fn secret_json_contains_secret_only_before_sealing() -> Result<()> {
        let secret = CredentialSecret::Http {
            headers: vec![SecretHeader {
                name: "Authorization".to_owned(),
                value: SecretString::from("Bearer secret-token".to_owned()),
            }],
        };
        let json = secret_json(&secret)?;
        assert!(String::from_utf8_lossy(&json).contains("secret-token"));

        let sealer = sealer()?;
        let ciphertext = seal(&sealer, "prod", &secret)?;
        assert!(!String::from_utf8_lossy(&ciphertext).contains("secret-token"));
        assert!(sealer.open(SECRET_DOMAIN, "other", &ciphertext).is_err());
        Ok(())
    }

    #[test]
    fn open_http_header_names_excludes_secret_values() -> Result<()> {
        let sealer = sealer()?;
        let secret = CredentialSecret::Http {
            headers: vec![SecretHeader {
                name: "X-Api-Key".to_owned(),
                value: SecretString::from("secret-token".to_owned()),
            }],
        };
        let ciphertext = seal(&sealer, "prod", &secret)?;

        let names = open_http_header_names(&sealer, "prod", &ciphertext)?;

        assert_eq!(names, ["X-Api-Key"]);
        Ok(())
    }

    #[test]
    fn client_key_seal_roundtrip_hides_key_and_binds_alias() -> Result<()> {
        let sealer = sealer()?;
        let key_pem = "-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----";
        let ciphertext = seal_client_key(&sealer, "prod", key_pem)?;
        assert!(!String::from_utf8_lossy(&ciphertext).contains("secret-key-material"));

        let opened = open_client_key(&sealer, "prod", &ciphertext)?;
        assert_eq!(opened, key_pem.as_bytes());

        assert!(open_client_key(&sealer, "other", &ciphertext).is_err());
        assert!(sealer.open(SECRET_DOMAIN, "prod", &ciphertext).is_err());
        Ok(())
    }

    #[test]
    fn client_identity_pem_adds_separator_when_needed() {
        let identity = client_identity_pem(b"cert", b"key");
        assert_eq!(identity, b"cert\nkey");

        let identity = client_identity_pem(b"cert\n", b"key");
        assert_eq!(identity, b"cert\nkey");
    }
}

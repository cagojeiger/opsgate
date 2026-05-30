use opsgate_core::crypto::Sealer;
use opsgate_core::{Error, Result};
use secrecy::SecretString;
use serde::Deserialize;

const SECRET_DOMAIN: &str = "credentials";

#[derive(Debug, Deserialize)]
pub(crate) struct SqlSecret {
    pub(crate) username: SecretString,
    pub(crate) password: SecretString,
}

pub(crate) fn open_sql_secret(
    sealer: &Sealer,
    alias: &str,
    ciphertext: &[u8],
) -> Result<SqlSecret> {
    let plaintext = sealer.open(SECRET_DOMAIN, alias, ciphertext)?;
    serde_json::from_slice::<SqlSecret>(&plaintext)
        .map_err(|error| Error::internal(format!("decode sql credential secret: {error}")))
}

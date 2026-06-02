mod error;
mod postgres;
use crate::crypto::Sealer;
use opsgate_core::{Error, Result};
use opsgate_model::credential::{Credential, CredentialTarget};

pub(crate) use crate::credential::secret::SqlSecret;
pub(crate) use error::{
    map_postgres_connect_error, map_postgres_query_error, map_postgres_schema_error,
    safe_error_record,
};
pub(crate) use postgres::{begin_read_only_connection, finish_read_only_result};

const MAX_DATABASE_NAME_LEN: usize = 63;

pub(crate) fn normalize_database_name(database: Option<String>) -> Result<Option<String>> {
    let Some(database) = database.map(|database| database.trim().to_owned()) else {
        return Ok(None);
    };
    if database.is_empty() {
        return Ok(None);
    }
    if database.len() > MAX_DATABASE_NAME_LEN
        || !database
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(Error::validation(
            "database must be 1-63 ASCII letters, digits, underscore, or hyphen",
        ));
    }
    Ok(Some(database))
}

pub(crate) fn credential_database_url(credential: &Credential) -> Result<&str> {
    match &credential.target {
        CredentialTarget::Sql { database_url } => Ok(database_url),
        CredentialTarget::Http { .. } => Err(Error::validation("credential target is not SQL")),
    }
}

pub(crate) fn open_sql_secret(
    sealer: &Sealer,
    alias: &str,
    ciphertext: &[u8],
) -> Result<SqlSecret> {
    crate::credential::secret::open_sql(sealer, alias, ciphertext)
}

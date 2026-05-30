mod postgres;
pub(crate) mod secret;

use opsgate_core::{Error, Result};
use opsgate_domain::credential::{Credential, CredentialTarget};

pub(crate) use postgres::{begin_read_only_connection, finish_read_only_result};
pub(crate) use secret::{SqlSecret, open_sql_secret};

pub(crate) fn credential_database_url(credential: &Credential) -> Result<&str> {
    match &credential.target {
        CredentialTarget::Sql { database_url } => Ok(database_url),
        CredentialTarget::Http { .. } => Err(Error::validation("credential target is not SQL")),
    }
}

use crate::crypto::Sealer;
use opsgate_core::Result;

pub(crate) use crate::credential::secret::SqlSecret;

pub fn open_sql_secret(sealer: &Sealer, alias: &str, ciphertext: &[u8]) -> Result<SqlSecret> {
    crate::credential::secret::open_sql(sealer, alias, ciphertext)
}

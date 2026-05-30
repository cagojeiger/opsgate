use opsgate_core::Result;
use opsgate_core::crypto::Sealer;

pub(crate) use crate::credential::secret::SqlSecret;

pub(crate) fn open_sql_secret(
    sealer: &Sealer,
    alias: &str,
    ciphertext: &[u8],
) -> Result<SqlSecret> {
    crate::credential::secret::open_sql(sealer, alias, ciphertext)
}

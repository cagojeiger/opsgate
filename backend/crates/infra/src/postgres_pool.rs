use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opsgate_core::{Error, Result};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use uuid::Uuid;

/// Drop a credential's whole pool after this long without use. Mirrors the
/// HTTP target client cache so idle targets release their sockets.
const POOL_CACHE_IDLE_TTL: Duration = Duration::from_secs(10 * 60);
/// Per-credential connection ceiling. Small: this is a single-user broker.
const POOL_MAX_CONNECTIONS: u32 = 4;
const POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
/// Close an individual pooled connection after this idle gap.
const POOL_CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const POOL_CONN_MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);

/// Per-credential Postgres connection pools, reused across `sql.query` and
/// `sql.schema` calls so each call no longer pays a fresh TCP + TLS + SCRAM
/// handshake.
#[derive(Clone)]
pub struct TargetPgPools {
    cached: Arc<Mutex<HashMap<Uuid, CachedPool>>>,
}

struct CachedPool {
    pool: PgPool,
    last_used: Instant,
}

impl Default for TargetPgPools {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetPgPools {
    pub fn new() -> Self {
        Self {
            cached: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Return the cached pool for this credential, building it lazily on first
    /// use. Credential target URL, secret, and TLS material are immutable, so
    /// the credential id is a stable cache key for the pool's lifetime.
    pub fn pool_for(&self, credential_id: Uuid, options: PgConnectOptions) -> Result<PgPool> {
        let now = Instant::now();
        let mut cached = self
            .cached
            .lock()
            .map_err(|_error| Error::internal("target pg pool cache lock poisoned"))?;
        cached.retain(|_id, entry| now.duration_since(entry.last_used) <= POOL_CACHE_IDLE_TTL);
        if let Some(entry) = cached.get_mut(&credential_id) {
            entry.last_used = now;
            return Ok(entry.pool.clone());
        }
        let pool = PgPoolOptions::new()
            .max_connections(POOL_MAX_CONNECTIONS)
            .acquire_timeout(POOL_ACQUIRE_TIMEOUT)
            .idle_timeout(POOL_CONN_IDLE_TIMEOUT)
            .max_lifetime(POOL_CONN_MAX_LIFETIME)
            .connect_lazy_with(options);
        cached.insert(
            credential_id,
            CachedPool {
                pool: pool.clone(),
                last_used: now,
            },
        );
        Ok(pool)
    }

    #[cfg(test)]
    fn cached_len(&self) -> Result<usize> {
        let cached = self
            .cached
            .lock()
            .map_err(|_error| Error::internal("target pg pool cache lock poisoned"))?;
        Ok(cached.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn options() -> Result<PgConnectOptions> {
        PgConnectOptions::from_str("postgres://user:pass@127.0.0.1:5432/app")
            .map_err(|error| Error::internal(error.to_string()))
    }

    #[tokio::test]
    async fn pool_is_reused_for_same_credential() -> Result<()> {
        let pools = TargetPgPools::new();
        let id = Uuid::from_u128(1);
        let _ = pools.pool_for(id, options()?)?;
        let _ = pools.pool_for(id, options()?)?;
        assert_eq!(pools.cached_len()?, 1);
        Ok(())
    }

    #[tokio::test]
    async fn distinct_credentials_get_distinct_pools() -> Result<()> {
        let pools = TargetPgPools::new();
        let _ = pools.pool_for(Uuid::from_u128(1), options()?)?;
        let _ = pools.pool_for(Uuid::from_u128(2), options()?)?;
        assert_eq!(pools.cached_len()?, 2);
        Ok(())
    }
}

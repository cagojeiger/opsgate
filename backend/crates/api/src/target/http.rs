use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opsgate_core::{Error, Result};
use opsgate_domain::credential::Credential;
use uuid::Uuid;

const CLIENT_CACHE_IDLE_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone)]
pub struct TargetHttpClients {
    shared: reqwest::Client,
    timeout: Duration,
    cached_tls: Arc<Mutex<HashMap<Uuid, CachedClient>>>,
}

impl TargetHttpClients {
    pub fn new(shared: reqwest::Client, timeout: Duration) -> Self {
        Self {
            shared,
            timeout,
            cached_tls: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn client_for(
        &self,
        credential: &Credential,
        tls_ca: Option<&[u8]>,
        guarded_addrs: Option<&[SocketAddr]>,
        url: &url::Url,
    ) -> Result<reqwest::Client> {
        if guarded_addrs.is_none() && tls_ca.is_none() {
            return Ok(self.shared.clone());
        }
        if let Some(guarded_addrs) = guarded_addrs {
            let host = url
                .host_str()
                .ok_or_else(|| Error::validation("credential endpoint requires host"))?;
            return build_client(self.timeout, tls_ca, Some((host, guarded_addrs)));
        }
        self.cached_tls_client(credential.id, tls_ca)
    }

    fn cached_tls_client(
        &self,
        credential_id: Uuid,
        tls_ca: Option<&[u8]>,
    ) -> Result<reqwest::Client> {
        let Some(tls_ca) = tls_ca else {
            return Ok(self.shared.clone());
        };
        let now = Instant::now();
        let mut cached = self
            .cached_tls
            .lock()
            .map_err(|_error| Error::internal("target client cache lock poisoned"))?;
        cached.retain(|_id, client| now.duration_since(client.last_used) <= CLIENT_CACHE_IDLE_TTL);
        if let Some(client) = cached.get_mut(&credential_id) {
            client.last_used = now;
            return Ok(client.client.clone());
        }
        let client = build_client(self.timeout, Some(tls_ca), None)?;
        cached.insert(
            credential_id,
            CachedClient {
                client: client.clone(),
                last_used: now,
            },
        );
        Ok(client)
    }
}

struct CachedClient {
    client: reqwest::Client,
    last_used: Instant,
}

fn build_client(
    timeout: Duration,
    tls_ca: Option<&[u8]>,
    guarded_target: Option<(&str, &[SocketAddr])>,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(tls_ca) = tls_ca {
        let pem = std::str::from_utf8(tls_ca)
            .map_err(|error| Error::validation(format!("invalid TLS server CA PEM: {error}")))?;
        opsgate_core::tls::parse_certificate_pem_bundle(pem)?;
        for cert in reqwest::Certificate::from_pem_bundle(tls_ca)
            .map_err(|error| Error::validation(format!("invalid TLS server CA PEM: {error}")))?
        {
            builder = builder.add_root_certificate(cert);
        }
    }
    if let Some((host, addrs)) = guarded_target {
        builder = builder.resolve_to_addrs(host, addrs);
    }
    builder
        .build()
        .map_err(|error| Error::internal(format!("build target HTTP client: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_client_rejects_bad_tls_ca() -> Result<()> {
        assert!(build_client(Duration::from_secs(1), Some(b"not pem"), None).is_err());
        Ok(())
    }
}

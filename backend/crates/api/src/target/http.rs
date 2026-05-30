use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opsgate_core::net::ssrf::is_blocked_target_ip;
use opsgate_core::{Error, Result};
use opsgate_domain::credential::Credential;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use uuid::Uuid;

const CLIENT_CACHE_IDLE_TTL: Duration = Duration::from_secs(10 * 60);

type DnsError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub struct TargetHttpClients {
    private_allowed: reqwest::Client,
    guarded_no_ca: reqwest::Client,
    timeout: Duration,
    cached_tls: Arc<Mutex<HashMap<TlsClientKey, CachedClient>>>,
}

impl TargetHttpClients {
    pub fn new(private_allowed: reqwest::Client, timeout: Duration) -> Result<Self> {
        Ok(Self {
            private_allowed,
            guarded_no_ca: build_client(timeout, None, true)?,
            timeout,
            cached_tls: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn client_for(
        &self,
        credential: &Credential,
        tls_ca: Option<&[u8]>,
        guard_private_network: bool,
    ) -> Result<reqwest::Client> {
        let Some(tls_ca) = tls_ca else {
            return if guard_private_network {
                Ok(self.guarded_no_ca.clone())
            } else {
                Ok(self.private_allowed.clone())
            };
        };
        self.cached_tls_client(credential.id, tls_ca, guard_private_network)
    }

    fn cached_tls_client(
        &self,
        credential_id: Uuid,
        tls_ca: &[u8],
        guard_private_network: bool,
    ) -> Result<reqwest::Client> {
        let key = TlsClientKey {
            credential_id,
            guard_private_network,
        };
        let now = Instant::now();
        let mut cached = self
            .cached_tls
            .lock()
            .map_err(|_error| Error::internal("target client cache lock poisoned"))?;
        cached.retain(|_id, client| now.duration_since(client.last_used) <= CLIENT_CACHE_IDLE_TTL);
        if let Some(client) = cached.get_mut(&key) {
            client.last_used = now;
            return Ok(client.client.clone());
        }
        // Credential updates intentionally cannot mutate endpoint, secret, or
        // TLS material. A credential id plus guard mode is therefore a stable
        // cache key for the lifetime of the registered target.
        let client = build_client(self.timeout, Some(tls_ca), guard_private_network)?;
        cached.insert(
            key,
            CachedClient {
                client: client.clone(),
                last_used: now,
            },
        );
        Ok(client)
    }

    #[cfg(test)]
    fn cached_tls_len(&self) -> Result<usize> {
        let cached = self
            .cached_tls
            .lock()
            .map_err(|_error| Error::internal("target client cache lock poisoned"))?;
        Ok(cached.len())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TlsClientKey {
    credential_id: Uuid,
    guard_private_network: bool,
}

struct CachedClient {
    client: reqwest::Client,
    last_used: Instant,
}

fn build_client(
    timeout: Duration,
    tls_ca: Option<&[u8]>,
    guard_private_network: bool,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    if guard_private_network {
        builder = builder.dns_resolver(Arc::new(GuardedResolver));
    }
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
    builder
        .build()
        .map_err(|error| Error::internal(format!("build target HTTP client: {error}")))
}

#[derive(Debug)]
struct GuardedResolver;

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            if let Ok(ip) = host.parse::<IpAddr>() {
                reject_blocked_ip(&host, ip)?;
                let addrs = vec![SocketAddr::new(ip, 0)];
                return Ok(Box::new(addrs.into_iter()) as Addrs);
            }

            let addrs = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|error| boxed_error(format!("resolve target host: {error}")))?
                .collect::<Vec<_>>();
            if addrs.is_empty() {
                return Err(boxed_error("resolve target host: no IPs"));
            }
            for addr in &addrs {
                reject_blocked_ip(&host, addr.ip())?;
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

fn reject_blocked_ip(_host: &str, ip: IpAddr) -> std::result::Result<(), DnsError> {
    if is_blocked_target_ip(ip) {
        return Err(boxed_error("target IP is private/link-local/loopback"));
    }
    Ok(())
}

fn boxed_error(message: impl Into<String>) -> DnsError {
    Box::new(std::io::Error::other(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use opsgate_domain::credential::{CredentialCategory, CredentialPolicy};

    #[test]
    fn target_client_rejects_bad_tls_ca() -> Result<()> {
        assert!(build_client(Duration::from_secs(1), Some(b"not pem"), false).is_err());
        Ok(())
    }

    #[test]
    fn no_ca_clients_do_not_enter_tls_cache() -> Result<()> {
        let clients = TargetHttpClients::new(reqwest::Client::new(), Duration::from_secs(1))?;
        let credential = credential(Uuid::nil(), false);
        let _client = clients.client_for(&credential, None, false)?;
        let _guarded_client = clients.client_for(&credential, None, true)?;
        assert_eq!(clients.cached_tls_len()?, 0);
        Ok(())
    }

    #[test]
    fn tls_ca_client_cache_is_per_credential_and_guard_mode() -> Result<()> {
        let clients = TargetHttpClients::new(reqwest::Client::new(), Duration::from_secs(1))?;
        let ca = valid_ca_pem();
        let first = credential(Uuid::from_u128(1), true);
        let second = credential(Uuid::from_u128(2), true);

        let _client = clients.client_for(&first, Some(ca.as_bytes()), true)?;
        let _same = clients.client_for(&first, Some(ca.as_bytes()), true)?;
        assert_eq!(clients.cached_tls_len()?, 1);

        let _unguarded = clients.client_for(&first, Some(ca.as_bytes()), false)?;
        assert_eq!(clients.cached_tls_len()?, 2);

        let _other = clients.client_for(&second, Some(ca.as_bytes()), true)?;
        assert_eq!(clients.cached_tls_len()?, 3);
        Ok(())
    }

    #[tokio::test]
    async fn guarded_resolver_blocks_private_literals() -> Result<()> {
        let resolver = GuardedResolver;
        let name = "127.0.0.1"
            .parse::<Name>()
            .map_err(|error| Error::internal(format!("parse name: {error}")))?;
        assert!(resolver.resolve(name).await.is_err());

        let name = "93.184.216.34"
            .parse::<Name>()
            .map_err(|error| Error::internal(format!("parse name: {error}")))?;
        let addrs = resolver
            .resolve(name)
            .await
            .map_err(|error| Error::internal(format!("resolve name: {error}")))?
            .collect::<Vec<_>>();
        assert_eq!(addrs, [SocketAddr::from(([93, 184, 216, 34], 0))]);
        Ok(())
    }

    fn credential(id: Uuid, has_tls_ca: bool) -> Credential {
        let now = Utc::now();
        Credential {
            id,
            owner_user_id: Uuid::nil(),
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod-api".to_owned(),
            endpoint: "https://api.example.test".to_owned(),
            description: String::new(),
            env: "prod".to_owned(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            has_tls_ca,
            created_at: now,
            updated_at: now,
        }
    }

    fn valid_ca_pem() -> &'static str {
        "-----BEGIN CERTIFICATE-----\nMIIDHzCCAgegAwIBAgIUR5kCYPXpbYN35M5bwwwjaBdpa5wwDQYJKoZIhvcNAQEL\nBQAwHzEdMBsGA1UEAwwUb3BzZ2F0ZS10ZXN0LXJvb3QtY2EwHhcNMjYwNTMwMDU0\nNjI5WhcNMzYwNTI3MDU0NjI5WjAfMR0wGwYDVQQDDBRvcHNnYXRlLXRlc3Qtcm9v\ndC1jYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8rA032g3ueF216\nAlyFxjPVti7+C641D3Y9bN+/pIRlBypf6rw0sxMtRGZwAllZuwp4Y9HqgWHFNuoQ\nz+MeKgL4y1AUOmafSIf4uVn8KktEguBOLmlrjKZ2TSMvooy+stQ/vbnUvKtl4V68\nxBn0Pem4606Y1NddvMh0HA08/FWn9/hJOX0vF+z1T2KrXtrML7tf1OZfWa4DspSe\nnxNE2W2eI8rdC4kHU6rvU5GfVyV7tvd37VBoL5xKIyRaqJG65rgmSdUMLuHjlI2A\nTfZ3kjothuvlOtus06YXsZxLQu+n3LEEXYv1UAK84Yiveo78W3DYZe5h+m6gmAH4\nqmrrZ88CAwEAAaNTMFEwHQYDVR0OBBYEFKyG33b7K3L7Gj9PbewP9bHxgqQjMB8G\nA1UdIwQYMBaAFKyG33b7K3L7Gj9PbewP9bHxgqQjMA8GA1UdEwEB/wQFMAMBAf8w\nDQYJKoZIhvcNAQELBQADggEBAFlKJP1sKkPagETWaYrK6/96XWlcr0bidIFgIUwO\nCc3SC4a921jpk+lUBXcZynOgxioT9VDE0eSsn3TIm60vLvjuYheTofqZx50WGiNr\n/HbiC29h2+5mqHvAlsDkyiz8h1xB13gykdXxblO1WtcIPc+J/HWgf0UuCVuTDC9z\nqCaGSkrE1GbVZ3IIn2Ng21aI6ODO45+5khk7kEMz8xpNibw4sJvTIkiKLfI/U8OA\n46B8eYczzIHR/Hr/uptFbQPjlt8BTedUQRtTrjizR4WEVYpGF6XQAEVw8lYCZ/hv\nahaDlUEG7pbFYIsn0MYLUFyiQjOyoweW/1W4YF/Oba7nUV8=\n-----END CERTIFICATE-----\n"
    }
}

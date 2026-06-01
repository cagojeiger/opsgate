use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;
use opsgate_core::{Error, Result};

use crate::network_guard::{BLOCKED_TARGET_IP_MESSAGE, ensure_target_ip_allowed};
use opsgate_model::credential::Credential;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use uuid::Uuid;

const CLIENT_CACHE_IDLE_TTL: Duration = Duration::from_secs(10 * 60);

type DnsError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub struct TargetHttpClients {
    private_allowed: reqwest::Client,
    guarded_no_ca: reqwest::Client,
    timeout: Duration,
    cached_tls: Cache<TlsClientKey, reqwest::Client>,
}

impl TargetHttpClients {
    pub fn new(timeout: Duration) -> Result<Self> {
        Ok(Self {
            private_allowed: build_client(timeout, TargetTls::default(), false)?,
            guarded_no_ca: build_client(timeout, TargetTls::default(), true)?,
            timeout,
            cached_tls: Cache::builder().time_to_idle(CLIENT_CACHE_IDLE_TTL).build(),
        })
    }

    pub fn request_for(
        &self,
        credential: &Credential,
        tls: TargetTls<'_>,
        method: reqwest::Method,
        url: &url::Url,
        guard_private_network: bool,
        allow_insecure_transport: bool,
    ) -> Result<reqwest::RequestBuilder> {
        ensure_url_allowed(url, guard_private_network, allow_insecure_transport)?;
        let client = self.client_for(credential, tls, guard_private_network)?;
        Ok(client.request(method, url.clone()))
    }

    fn client_for(
        &self,
        credential: &Credential,
        tls: TargetTls<'_>,
        guard_private_network: bool,
    ) -> Result<reqwest::Client> {
        if tls.server_ca.is_none() && tls.client_identity.is_none() {
            return if guard_private_network {
                Ok(self.guarded_no_ca.clone())
            } else {
                Ok(self.private_allowed.clone())
            };
        }
        self.cached_tls_client(credential.id, tls, guard_private_network)
    }

    fn cached_tls_client(
        &self,
        credential_id: Uuid,
        tls: TargetTls<'_>,
        guard_private_network: bool,
    ) -> Result<reqwest::Client> {
        let key = TlsClientKey {
            credential_id,
            guard_private_network,
        };
        if let Some(client) = self.cached_tls.get(&key) {
            return Ok(client);
        }
        // Credential updates intentionally cannot mutate target URL, secret, or
        // TLS material. A credential id plus guard mode is therefore a stable
        // cache key for the lifetime of the registered target.
        let client = build_client(self.timeout, tls, guard_private_network)?;
        self.cached_tls.insert(key, client.clone());
        Ok(client)
    }

    #[cfg(test)]
    fn cached_tls_len(&self) -> Result<usize> {
        self.cached_tls.run_pending_tasks();
        usize::try_from(self.cached_tls.entry_count())
            .map_err(|error| Error::internal(format!("target client cache size overflow: {error}")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TlsClientKey {
    credential_id: Uuid,
    guard_private_network: bool,
}

/// Per-credential TLS material applied when building a target client.
/// `server_ca` is the PEM CA bundle for verifying the target. `client_identity`
/// is the combined client certificate chain plus unsealed private key PEM used
/// for mutual-TLS client authentication.
#[derive(Debug, Clone, Copy, Default)]
pub struct TargetTls<'a> {
    pub server_ca: Option<&'a [u8]>,
    pub client_identity: Option<&'a [u8]>,
}

fn build_client(
    timeout: Duration,
    tls: TargetTls<'_>,
    guard_private_network: bool,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if guard_private_network {
        builder = builder.dns_resolver(Arc::new(GuardedResolver));
    }
    if let Some(tls_ca) = tls.server_ca {
        let pem = std::str::from_utf8(tls_ca)
            .map_err(|error| Error::validation(format!("invalid TLS server CA PEM: {error}")))?;
        opsgate_core::tls::parse_certificate_pem_bundle(pem)?;
        for cert in reqwest::Certificate::from_pem_bundle(tls_ca)
            .map_err(|error| Error::validation(format!("invalid TLS server CA PEM: {error}")))?
        {
            builder = builder.add_root_certificate(cert);
        }
    }
    if let Some(client_identity) = tls.client_identity {
        let identity = reqwest::Identity::from_pem(client_identity).map_err(|error| {
            Error::validation(format!("invalid client certificate identity: {error}"))
        })?;
        builder = builder.identity(identity);
    }
    builder
        .build()
        .map_err(|error| Error::internal(format!("build target HTTP client: {error}")))
}

#[derive(Debug)]
struct GuardedResolver;

pub fn ensure_url_allowed(
    url: &url::Url,
    guard_private_network: bool,
    allow_insecure_transport: bool,
) -> Result<()> {
    match url.scheme() {
        "https" => {}
        "http" if !guard_private_network && allow_insecure_transport => {}
        "http" => {
            return Err(Error::validation(
                "target URL http requires allow_private_network=true and allow_insecure_transport=true",
            ));
        }
        _ => return Err(Error::validation("target URL must use http or https")),
    }
    if !guard_private_network {
        return Ok(());
    }
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ensure_target_ip_allowed(IpAddr::V4(ip), false),
        Some(url::Host::Ipv6(ip)) => ensure_target_ip_allowed(IpAddr::V6(ip), false),
        Some(url::Host::Domain(_host)) => Ok(()),
        None => Err(Error::validation("target URL requires host")),
    }
}

pub fn map_send_error(error: reqwest::Error) -> Error {
    if has_blocked_target_source(&error) {
        return Error::user_safe(
            "target_private_network_blocked",
            "Target resolved to a private, loopback, or link-local address.",
            Some("Use allow_private_network only for trusted internal targets."),
        );
    }
    if error.is_timeout() {
        return Error::user_safe(
            "target_timeout",
            "Target request timed out before receiving a response.",
            Some("Check target availability, reduce the request scope, or retry later."),
        );
    }
    if error.is_connect() {
        return Error::user_safe(
            "target_unreachable",
            "Target could not be reached before receiving a response.",
            Some(
                "Check credential target, network reachability, TLS CA, and private/insecure transport settings.",
            ),
        );
    }
    Error::internal("target request failed")
}

fn has_blocked_target_source(error: &reqwest::Error) -> bool {
    let mut source = std::error::Error::source(error);
    while let Some(error) = source {
        if error.to_string().contains(BLOCKED_TARGET_IP_MESSAGE) {
            return true;
        }
        source = error.source();
    }
    false
}

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
    ensure_target_ip_allowed(ip, false).map_err(|_error| boxed_error(BLOCKED_TARGET_IP_MESSAGE))
}

fn boxed_error(message: impl Into<String>) -> DnsError {
    Box::new(std::io::Error::other(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use opsgate_model::credential::{CredentialCategory, CredentialPolicy, CredentialTarget};

    #[test]
    fn target_client_rejects_bad_tls_ca() -> Result<()> {
        let tls = TargetTls {
            server_ca: Some(b"not pem"),
            client_identity: None,
        };
        assert!(build_client(Duration::from_secs(1), tls, false).is_err());
        Ok(())
    }

    #[test]
    fn target_client_rejects_bad_client_identity() -> Result<()> {
        let tls = TargetTls {
            server_ca: None,
            client_identity: Some(b"not a client identity"),
        };
        assert!(build_client(Duration::from_secs(1), tls, false).is_err());
        Ok(())
    }

    #[test]
    fn no_ca_clients_do_not_enter_tls_cache() -> Result<()> {
        let clients = TargetHttpClients::new(Duration::from_secs(1))?;
        let credential = credential(Uuid::nil(), false);
        let _client = clients.client_for(&credential, TargetTls::default(), false)?;
        let _guarded_client = clients.client_for(&credential, TargetTls::default(), true)?;
        assert_eq!(clients.cached_tls_len()?, 0);
        Ok(())
    }

    #[test]
    fn tls_ca_client_cache_is_per_credential_and_guard_mode() -> Result<()> {
        let clients = TargetHttpClients::new(Duration::from_secs(1))?;
        let ca = valid_ca_pem();
        let tls = TargetTls {
            server_ca: Some(ca.as_bytes()),
            client_identity: None,
        };
        let first = credential(Uuid::from_u128(1), true);
        let second = credential(Uuid::from_u128(2), true);

        let _client = clients.client_for(&first, tls, true)?;
        let _same = clients.client_for(&first, tls, true)?;
        assert_eq!(clients.cached_tls_len()?, 1);

        let _unguarded = clients.client_for(&first, tls, false)?;
        assert_eq!(clients.cached_tls_len()?, 2);

        let _other = clients.client_for(&second, tls, true)?;
        assert_eq!(clients.cached_tls_len()?, 3);
        Ok(())
    }

    #[test]
    fn client_identity_enters_per_credential_tls_cache() -> Result<()> {
        let clients = TargetHttpClients::new(Duration::from_secs(1))?;
        let identity = valid_client_identity_pem();
        let tls = TargetTls {
            server_ca: None,
            client_identity: Some(identity.as_bytes()),
        };
        let credential = credential(Uuid::from_u128(7), false);

        let _client = clients.client_for(&credential, tls, true)?;
        let _same = clients.client_for(&credential, tls, true)?;
        assert_eq!(clients.cached_tls_len()?, 1);

        let _unguarded = clients.client_for(&credential, tls, false)?;
        assert_eq!(clients.cached_tls_len()?, 2);
        Ok(())
    }

    #[test]
    fn guarded_http_preflight_blocks_private_url_literals() -> Result<()> {
        for raw in [
            "https://127.0.0.1/status",
            "https://[::1]/status",
            "https://[::ffff:127.0.0.1]/status",
        ] {
            let url = url::Url::parse(raw)
                .map_err(|error| Error::internal(format!("parse test URL: {error}")))?;
            let err = ensure_url_allowed(&url, true, false)
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default();
            assert!(err.contains("private/link-local/loopback"), "{raw}: {err}");
        }
        let public = url::Url::parse("https://93.184.216.34/status")
            .map_err(|error| Error::internal(format!("parse test URL: {error}")))?;
        assert!(ensure_url_allowed(&public, true, false).is_ok());
        assert!(ensure_url_allowed(&public, false, false).is_ok());
        Ok(())
    }

    #[test]
    fn insecure_http_requires_explicit_private_transport_opt_in() -> Result<()> {
        let url = url::Url::parse("http://10.0.0.10/status")
            .map_err(|error| Error::internal(format!("parse test URL: {error}")))?;
        let err = ensure_url_allowed(&url, false, false)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(err.contains("allow_private_network"));
        assert!(ensure_url_allowed(&url, false, true).is_ok());
        Ok(())
    }

    #[test]
    fn guarded_resolver_blocks_ipv4_mapped_private_literals() {
        let err = reject_blocked_ip(
            "::ffff:127.0.0.1",
            IpAddr::V6(std::net::Ipv6Addr::new(
                0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001,
            )),
        )
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
        assert!(err.contains("private/link-local/loopback"));
    }

    #[tokio::test]
    async fn send_error_preserves_guarded_dns_block_reason() -> Result<()> {
        #[derive(Debug)]
        struct AlwaysBlockedResolver;

        impl Resolve for AlwaysBlockedResolver {
            fn resolve(&self, _name: Name) -> Resolving {
                Box::pin(async { Err(boxed_error(BLOCKED_TARGET_IP_MESSAGE)) })
            }
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(100))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .dns_resolver(Arc::new(AlwaysBlockedResolver))
            .build()
            .map_err(|error| Error::internal(format!("build test client: {error}")))?;
        let error = client
            .get("http://example.test/")
            .send()
            .await
            .err()
            .ok_or_else(|| Error::internal("test request unexpectedly succeeded"))?;
        let mapped = map_send_error(error);
        let Error::UserSafe {
            kind,
            message,
            hint,
        } = mapped
        else {
            return Err(Error::internal("expected user-safe blocked target error"));
        };
        assert_eq!(kind, "target_private_network_blocked");
        assert!(message.contains("private"));
        assert!(
            hint.as_deref()
                .is_some_and(|hint| hint.contains("allow_private_network"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_timeout_maps_to_user_safe_retry_guidance() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| Error::internal(format!("bind test listener: {error}")))?;
        let addr = listener
            .local_addr()
            .map_err(|error| Error::internal(format!("read listener addr: {error}")))?;
        let _server = tokio::spawn(async move {
            if let Ok((_stream, _peer)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(50))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|error| Error::internal(format!("build test client: {error}")))?;
        let error = client
            .get(format!("http://{addr}/"))
            .send()
            .await
            .err()
            .ok_or_else(|| Error::internal("test request unexpectedly succeeded"))?;

        let mapped = map_send_error(error);

        let Error::UserSafe {
            kind,
            message,
            hint,
        } = mapped
        else {
            return Err(Error::internal("expected user-safe timeout error"));
        };
        assert_eq!(kind, "target_timeout");
        assert!(message.contains("timed out"));
        assert!(hint.as_deref().is_some_and(|hint| hint.contains("retry")));
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
            target: CredentialTarget::Http {
                origin: "https://api.example.test".to_owned(),
                base_path: "/".to_owned(),
            },
            description: String::new(),
            env: "prod".to_owned(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            has_tls_ca,
            has_client_cert: false,
            created_at: now,
            updated_at: now,
        }
    }

    fn valid_client_identity_pem() -> &'static str {
        concat!(
            "-----BEGIN CERTIFICATE-----\nMIIDHTCCAgWgAwIBAgIUeHo/5+8sjg/PpHE9InlaPTbT/gEwDQYJKoZIhvcNAQEL\nBQAwHjEcMBoGA1UEAwwTb3BzZ2F0ZS10ZXN0LWNsaWVudDAeFw0yNjA2MDExMjU5\nMDlaFw0zNjA1MjkxMjU5MDlaMB4xHDAaBgNVBAMME29wc2dhdGUtdGVzdC1jbGll\nbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCgRERa2kSLK798wN8b\nExvfwxOJowMy+CXRwdLRzXmkY72pEpE2fQFD26epr7QtoBg5Zh06o6yYFPB9DExo\nvW6X9vx02yD8gwQIVzX/jfif2KlqTmIjBDZ4SQcdvmIkzgKkDLz0+52vLFj4pXnw\nogHHwk8R9XmH/DCaFBocvooxVPJBQ55RHiXZe29bUw70+82V5QVZzzSqVeou7XhF\nj+as3CU04QXtjaDbWkOUV43vYouEEpo9nROLMOXXgIPlu/War3EVPApdepgBRYVg\nRV02twZ8XrYykS8Lkstug/Z428NMAsPn119B2eipWiMGSQzi7iCn6Fld9ZTifSO5\n6wS3AgMBAAGjUzBRMB0GA1UdDgQWBBQ/Xl2M8H9mqD1VSWWI9eWswWbV4zAfBgNV\nHSMEGDAWgBQ/Xl2M8H9mqD1VSWWI9eWswWbV4zAPBgNVHRMBAf8EBTADAQH/MA0G\nCSqGSIb3DQEBCwUAA4IBAQAJoHc0RiDYRrpq7AfCEHifZymX9pcDiVzH0qHND+Um\n8BuhnLlSj7gtJpzRs8bBHnSHRtvG/+FtzA0pUbiNUy0OAqqGRg9PQ8dzmspVrZ4Y\nmxRx+jnBf98C8c5rzM5+qhUed6/RVUs+SmKmwc5sqZN3niE6ZQKEcnCNnCz5grh8\nYWxQzH2eBRhLBqbUeeH9AFO4k9SmFdyZX1HPulZQIe4JOKlqaBJ2tBmM9fwi/4Ff\npsjSET+mFZCBbvbWoXeGQB5tOFXCwv5aUMZuJHBk94q0k8KMYb665v+sEdbpmU69\nsS2tHfA1kgZmZ6uVaLaUqTmr8VAx60+z7YZQwxHJI/44\n-----END CERTIFICATE-----\n",
            "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCgRERa2kSLK798\nwN8bExvfwxOJowMy+CXRwdLRzXmkY72pEpE2fQFD26epr7QtoBg5Zh06o6yYFPB9\nDExovW6X9vx02yD8gwQIVzX/jfif2KlqTmIjBDZ4SQcdvmIkzgKkDLz0+52vLFj4\npXnwogHHwk8R9XmH/DCaFBocvooxVPJBQ55RHiXZe29bUw70+82V5QVZzzSqVeou\n7XhFj+as3CU04QXtjaDbWkOUV43vYouEEpo9nROLMOXXgIPlu/War3EVPApdepgB\nRYVgRV02twZ8XrYykS8Lkstug/Z428NMAsPn119B2eipWiMGSQzi7iCn6Fld9ZTi\nfSO56wS3AgMBAAECggEAT9NA4qm1m0YKhfZBCei+KPkuqY7eoIv1tmDegy5faLBf\nPq+nUWb48tYc0AlaaqFDf49rfpIYfNVtJTOzeTXlOF7GRuQALZWKNCdQF34cuG0/\nkNoCymMmSEpDd56knqVXrmND2Jfc5evmUs6FCoR+84LGRHEqe79ya8QYb3m+NixJ\n6dtHqcxmqCKip0IePQXYXp9roNVJdggJn3t30PGqlpkP873YKdRW1yZpKG9r1UG1\nV75b6tDhW7J9xo/ZKGyxuXv1wWQDrC+uhpwjKAEY414v8bdaT0S/pMPgVUkyInjc\nfa0Nw8SbmNV3DhRqtWvzXmquum7Rbud3Q161k3MOmQKBgQDRn/FQDj1mVx2CyU+w\nci5MKz1OAlyvH/LmuR3D0lYMoorQ9tEOnD7Bz//D+7ttZGbmGMO56gjkDuR/Vl5k\nSfRvzuf+HG+7U15QQveaqCmmp2369ux7S+1k4D1aFNo7H1szTZGcSleLWAs1em7M\npCoqgbAAS1hpn/UxaJCAW99cSQKBgQDDuPAS6IcIov5UQ+U7+KfjwCHxriOwqQcO\n/hQg8MX7XneImcpPNiM56XfFrqKQUTftUueLsT9uCXkeZ1WUnvXwAY7O9UlTfRJJ\nhXbcVLfBxVjmcUjeS5mpajEIdH36nDD1BGrsoASNULR2roJ+AkucpySPAM/itceH\nZHenxw1Y/wKBgGWjRz2pqduVIZnoQdsrgYcs7+yC+K1wsDVuTCBGO7KknOn0wihz\nWXpff4Nm6tl/dOTb3QqnjugE0IVtOxclRH9xsspiv0n0giYoUiWKo6dKRukIEGE3\nz0K59wVWVvmTmoSld5Rv90J4zfaABnjyn/88IjoCTjvoctoh+O5DnWkBAoGAGT3M\nmGOspox+yFdJRQa4gELTHdwbdjkWU/Som+bxYY25VMCgur58pIdbjv8KsBoJYG4E\ntptRVtuZ5zXkb5pglWdeB4rSvhWvOhQgVCII4NCWuoF5qFGPq62qTTDY3m0uUysS\nrxmj/KWf4H55Dc81+SoFKPwt00smRGvMkrK1IfkCgYEAhzRFR0qadgVT3qJHF9xQ\nxRKOd0rJbv3CACVVUQ/qXx3Uei/4pKdVMpecWE3Y2mAs6Thh9rPwjjXj1BAOQXnm\nqF+NE0+7QiEcE2p+H83VBfvecSkPpNGMSTQmTNQZwmCRQJ1knTHzc5+e89dZTsUK\nJhwM1YsTOoRWQJapergyhTw=\n-----END PRIVATE KEY-----\n",
        )
    }

    fn valid_ca_pem() -> &'static str {
        "-----BEGIN CERTIFICATE-----\nMIIDHzCCAgegAwIBAgIUR5kCYPXpbYN35M5bwwwjaBdpa5wwDQYJKoZIhvcNAQEL\nBQAwHzEdMBsGA1UEAwwUb3BzZ2F0ZS10ZXN0LXJvb3QtY2EwHhcNMjYwNTMwMDU0\nNjI5WhcNMzYwNTI3MDU0NjI5WjAfMR0wGwYDVQQDDBRvcHNnYXRlLXRlc3Qtcm9v\ndC1jYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8rA032g3ueF216\nAlyFxjPVti7+C641D3Y9bN+/pIRlBypf6rw0sxMtRGZwAllZuwp4Y9HqgWHFNuoQ\nz+MeKgL4y1AUOmafSIf4uVn8KktEguBOLmlrjKZ2TSMvooy+stQ/vbnUvKtl4V68\nxBn0Pem4606Y1NddvMh0HA08/FWn9/hJOX0vF+z1T2KrXtrML7tf1OZfWa4DspSe\nnxNE2W2eI8rdC4kHU6rvU5GfVyV7tvd37VBoL5xKIyRaqJG65rgmSdUMLuHjlI2A\nTfZ3kjothuvlOtus06YXsZxLQu+n3LEEXYv1UAK84Yiveo78W3DYZe5h+m6gmAH4\nqmrrZ88CAwEAAaNTMFEwHQYDVR0OBBYEFKyG33b7K3L7Gj9PbewP9bHxgqQjMB8G\nA1UdIwQYMBaAFKyG33b7K3L7Gj9PbewP9bHxgqQjMA8GA1UdEwEB/wQFMAMBAf8w\nDQYJKoZIhvcNAQELBQADggEBAFlKJP1sKkPagETWaYrK6/96XWlcr0bidIFgIUwO\nCc3SC4a921jpk+lUBXcZynOgxioT9VDE0eSsn3TIm60vLvjuYheTofqZx50WGiNr\n/HbiC29h2+5mqHvAlsDkyiz8h1xB13gykdXxblO1WtcIPc+J/HWgf0UuCVuTDC9z\nqCaGSkrE1GbVZ3IIn2Ng21aI6ODO45+5khk7kEMz8xpNibw4sJvTIkiKLfI/U8OA\n46B8eYczzIHR/Hr/uptFbQPjlt8BTedUQRtTrjizR4WEVYpGF6XQAEVw8lYCZ/hv\nahaDlUEG7pbFYIsn0MYLUFyiQjOyoweW/1W4YF/Oba7nUV8=\n-----END CERTIFICATE-----\n"
    }
}

use std::net::IpAddr;

use opsgate_core::{Error, Result};
use opsgate_model::credential::{CredentialCategory, CredentialTarget, RegisterCredentialInput};

use opsgate_infra::network_guard::{BLOCKED_TARGET_IP_MESSAGE, target_ip_is_blocked};

#[derive(Clone)]
pub(super) enum EndpointResolver {
    System,
    #[cfg(test)]
    Fixed(Vec<IpAddr>),
}

impl EndpointResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>> {
        match self {
            Self::System => tokio::net::lookup_host((host, port))
                .await
                .map_err(|error| Error::validation(format!("resolve target host: {error}")))
                .map(|addrs| addrs.map(|addr| addr.ip()).collect()),
            #[cfg(test)]
            Self::Fixed(ips) => Ok(ips.clone()),
        }
    }
}

pub(super) async fn validate_register_target_ips(
    resolver: &EndpointResolver,
    input: &RegisterCredentialInput,
) -> Result<()> {
    if input.allow_private_network {
        return Ok(());
    }
    let raw_url = match &input.target {
        CredentialTarget::Http { origin, .. } => origin,
        CredentialTarget::Sql { database_url } => database_url,
    };
    let url = url::Url::parse(raw_url)
        .map_err(|error| Error::validation(format!("target URL: {error}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| Error::validation("target requires host"))?;
    let default_port = match input.category {
        CredentialCategory::Http => 443,
        CredentialCategory::Sql => 5432,
    };
    let port = url.port().unwrap_or(default_port);
    let ips = resolver.resolve(host, port).await?;
    if ips.is_empty() {
        return Err(Error::validation("resolve target host: no IPs"));
    }
    if ips.into_iter().any(target_ip_is_blocked) {
        return Err(Error::validation(BLOCKED_TARGET_IP_MESSAGE));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use opsgate_core::Result;
    use opsgate_model::credential::{CredentialPolicy, RegisterCredentialInput};

    use super::super::input::{RegisterHttpCredentialInput, SecretHeaderInput};
    use super::*;

    fn http_input(allow_private_network: bool) -> RegisterCredentialInput {
        RegisterHttpCredentialInput {
            provider: "k8s".to_owned(),
            alias: "prod".to_owned(),
            origin: "https://service.example.test".to_owned(),
            base_path: String::new(),
            secret_headers: vec![SecretHeaderInput {
                name: "Authorization".to_owned(),
                value: "Bearer secret-token".to_owned(),
            }],
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network,
            allow_insecure_transport: false,
            tls_server_ca: String::new(),
        }
        .into_domain()
    }

    #[tokio::test]
    async fn rejects_private_register_target_ip() -> Result<()> {
        let resolver = EndpointResolver::Fixed(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
        let err = validate_register_target_ips(&resolver, &http_input(false))
            .await
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(err.contains("private/link-local/loopback"));
        assert!(!err.contains("secret-token"));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_ipv4_mapped_private_register_target_ip() -> Result<()> {
        let resolver = EndpointResolver::Fixed(vec![IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001,
        ))]);
        let err = validate_register_target_ips(&resolver, &http_input(false))
            .await
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(err.contains("private/link-local/loopback"));
        assert!(!err.contains("::ffff"));
        Ok(())
    }

    #[tokio::test]
    async fn allows_private_register_target_when_explicitly_enabled() -> Result<()> {
        let resolver = EndpointResolver::Fixed(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
        assert!(
            validate_register_target_ips(&resolver, &http_input(true))
                .await
                .is_ok()
        );
        Ok(())
    }
}

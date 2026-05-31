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

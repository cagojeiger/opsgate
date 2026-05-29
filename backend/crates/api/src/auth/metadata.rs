use axum::Json;
use axum::http::HeaderValue;
use opsgate_core::Config;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedResourceUrl {
    pub route_path: String,
    pub full_url: String,
}

pub fn protected_resource_metadata_url(resource_url: &str) -> ProtectedResourceUrl {
    let trimmed = resource_url.trim_end_matches('/');
    let (origin, resource_path) = split_origin_and_path(trimmed);
    let path = resource_path.trim_matches('/');
    let route_path = if path.is_empty() {
        "/.well-known/oauth-protected-resource".to_owned()
    } else {
        format!("/.well-known/oauth-protected-resource/{path}")
    };
    let full_url = format!("{origin}{route_path}");
    ProtectedResourceUrl {
        route_path,
        full_url,
    }
}

fn split_origin_and_path(value: &str) -> (&str, &str) {
    let Some((scheme, rest)) = value.split_once("://") else {
        return (value, "");
    };
    if let Some((host, path)) = rest.split_once('/') {
        let origin_len = scheme.len() + 3 + host.len();
        (&value[..origin_len], path)
    } else {
        (value, "")
    }
}

pub fn challenge_header(meta_url: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("Bearer resource_metadata=\"{meta_url}\""))
        .unwrap_or_else(|_error| HeaderValue::from_static("Bearer"))
}

#[derive(Debug, Serialize)]
pub struct ProtectedResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<&'static str>,
    bearer_methods_supported: Vec<&'static str>,
}

pub async fn protected_resource_metadata(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
) -> Json<ProtectedResourceMetadata> {
    Json(protected_resource_metadata_for_config(&state.config))
}

pub fn protected_resource_metadata_for_config(config: &Config) -> ProtectedResourceMetadata {
    ProtectedResourceMetadata {
        resource: config.resource_url.clone(),
        authorization_servers: vec![config.authgate_url.clone()],
        scopes_supported: vec!["openid", "profile", "email", "offline_access"],
        bearer_methods_supported: vec!["header"],
    }
}

#[cfg(test)]
mod tests {
    use super::protected_resource_metadata_url;

    #[test]
    fn metadata_url_for_root_resource() {
        let got = protected_resource_metadata_url("http://localhost:9091");
        assert_eq!(got.route_path, "/.well-known/oauth-protected-resource");
        assert_eq!(
            got.full_url,
            "http://localhost:9091/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn metadata_url_for_mcp_resource() {
        let got = protected_resource_metadata_url("http://localhost:9091/mcp");
        assert_eq!(got.route_path, "/.well-known/oauth-protected-resource/mcp");
        assert_eq!(
            got.full_url,
            "http://localhost:9091/.well-known/oauth-protected-resource/mcp"
        );
    }
}

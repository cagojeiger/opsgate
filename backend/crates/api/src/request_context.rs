use axum::http::HeaderMap;
use axum::http::header::USER_AGENT;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RequestMetadata {
    pub request_id: Option<String>,
    pub remote_ip: Option<String>,
    pub user_agent: Option<String>,
}

impl RequestMetadata {
    pub(crate) fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            request_id: header_value(headers, "x-request-id"),
            remote_ip: remote_ip(headers),
            user_agent: headers
                .get(USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
        }
    }
}

fn header_value(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn remote_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;

    use super::RequestMetadata;

    #[test]
    fn request_metadata_trims_headers_and_uses_first_forwarded_ip()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", " req-1 ".parse()?);
        headers.insert("x-forwarded-for", " 203.0.113.9, 10.0.0.1 ".parse()?);
        headers.insert("user-agent", " opsgate-test ".parse()?);

        let metadata = RequestMetadata::from_headers(&headers);

        assert_eq!(metadata.request_id.as_deref(), Some("req-1"));
        assert_eq!(metadata.remote_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(metadata.user_agent.as_deref(), Some("opsgate-test"));
        Ok(())
    }
}

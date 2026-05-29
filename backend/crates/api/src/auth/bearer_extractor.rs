use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName};
use axum::response::Response;
use opsgate_domain::Caller;

use crate::auth::bearer::{RequestMeta, verify_bearer};
use crate::auth::bearer_error::{AuthError, auth_error_response};
use crate::state::AppState;

pub fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() { None } else { Some(token) }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedCaller(pub Caller);

impl FromRequestParts<AppState> for AuthenticatedCaller {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer(&parts.headers)
            .ok_or_else(|| auth_error_response(state, AuthError::MissingToken))?;
        let meta = request_meta_from_parts(parts);
        verify_bearer(state, token, meta)
            .await
            .map(Self)
            .map_err(|error| auth_error_response(state, error))
    }
}

pub fn request_meta_from_parts(parts: &Parts) -> RequestMeta {
    RequestMeta {
        remote_ip: None,
        user_agent: header_to_string(&parts.headers, axum::http::header::USER_AGENT),
        request_id: header_to_string(&parts.headers, HeaderName::from_static("x-request-id")),
    }
}

fn header_to_string(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;
    use axum::http::header::AUTHORIZATION;

    use super::extract_bearer;

    #[test]
    fn extracts_bearer_token() -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer abc".parse()?);
        assert_eq!(extract_bearer(&headers), Some("abc"));
        Ok(())
    }

    #[test]
    fn rejects_missing_or_empty_bearer() -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        assert_eq!(extract_bearer(&headers), None);
        headers.insert(AUTHORIZATION, "Bearer   ".parse()?);
        assert_eq!(extract_bearer(&headers), None);
        headers.insert(AUTHORIZATION, "Basic abc".parse()?);
        assert_eq!(extract_bearer(&headers), None);
        Ok(())
    }
}

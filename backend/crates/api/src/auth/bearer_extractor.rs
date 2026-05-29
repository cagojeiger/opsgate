use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
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
        verify_bearer(state, token, RequestMeta)
            .await
            .map(Self)
            .map_err(|error| auth_error_response(state, error))
    }
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

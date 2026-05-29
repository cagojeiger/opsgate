use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;

pub fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() { None } else { Some(token) }
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

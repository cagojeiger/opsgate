use std::collections::BTreeMap;
use std::time::Instant;

use crate::llm_output::{JsonOutputOptions, build_json_output};
use opsgate_core::{Error, Result};
use opsgate_model::credential::{Credential, CredentialTarget, SecretHeader};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use secrecy::ExposeSecret;

use crate::audit::runtime::reason;
use opsgate_infra::http::TargetHttpClients;

use super::input::{MAX_MAX_BYTES, NormalizedApiCallInput};
use super::output::ApiCallOutput;

pub(super) struct CallExecutionError {
    pub(super) kind: &'static str,
    pub(super) message: String,
    pub(super) error: Error,
}

impl CallExecutionError {
    fn new(kind: &'static str, message: impl Into<String>, error: Error) -> Self {
        Self {
            kind,
            message: message.into(),
            error,
        }
    }

    fn target_request(error: Error) -> Self {
        match &error {
            Error::UserSafe { kind, message, .. } => Self::new(kind, message.clone(), error),
            _ => Self::new(
                reason::TARGET_REQUEST_FAILED,
                "target request failed",
                error,
            ),
        }
    }
}

pub(super) async fn execute_target_call(
    target_clients: &TargetHttpClients,
    credential: &Credential,
    tls_ca: Option<&[u8]>,
    input: &NormalizedApiCallInput,
    secret: &[SecretHeader],
) -> std::result::Result<ApiCallOutput, CallExecutionError> {
    let url = build_target_url(&credential.target, input).map_err(|error| {
        CallExecutionError::new(reason::TARGET_URL_FAILED, "target URL build failed", error)
    })?;
    let started = Instant::now();
    let mut response = send_target(target_clients, credential, tls_ca, &url, input, secret)
        .await
        .map_err(CallExecutionError::target_request)?;
    let status_code = i32::from(response.status.as_u16());
    let headers = filtered_response_headers(&response.headers);
    if !response_content_type_is_json(&response.headers) {
        return Err(CallExecutionError::new(
            reason::TARGET_NOT_JSON,
            "target response is not JSON",
            Error::validation("target response is not JSON"),
        ));
    }
    let (body, original_bytes, transport_truncated) =
        read_capped(&mut response.response, MAX_MAX_BYTES)
            .await
            .map_err(|error| {
                CallExecutionError::new(
                    reason::TARGET_READ_FAILED,
                    "read target response failed",
                    error,
                )
            })?;
    let latency_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
    let shaped = build_json_output(
        &body,
        JsonOutputOptions {
            max_bytes: input.max_bytes,
            max_allowed_bytes: MAX_MAX_BYTES,
            json_paths: input.jsonpath.clone(),
            transport_truncated,
            original_bytes: Some(original_bytes),
        },
    )
    .map_err(|error| {
        CallExecutionError::new(reason::OUTPUT_BUILD_FAILED, "output build failed", error)
    })?;
    Ok(ApiCallOutput {
        status_code,
        headers,
        body: shaped.body,
        truncated: shaped.truncated,
        original_bytes: shaped.original_bytes,
        returned_bytes: shaped.returned_bytes,
        latency_ms,
        more: shaped.more,
    })
}

async fn send_target(
    target_clients: &TargetHttpClients,
    credential: &Credential,
    tls_ca: Option<&[u8]>,
    url: &url::Url,
    input: &NormalizedApiCallInput,
    secret: &[SecretHeader],
) -> Result<TargetResponseHead> {
    let method = reqwest::Method::from_bytes(input.method.as_bytes())
        .map_err(|error| Error::validation(format!("invalid method: {error}")))?;
    let mut request = target_clients.request_for(
        credential,
        tls_ca,
        method,
        url,
        !credential.allow_private_network,
        credential.allow_insecure_transport,
    )?;
    let mut headers = HeaderMap::new();
    if !input
        .headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case("accept"))
    {
        headers.insert(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("application/json"),
        );
    }
    for (name, value) in &input.headers {
        headers.insert(header_name(name)?, header_value(value)?);
    }
    for header in secret {
        headers.insert(
            header_name(&header.name)?,
            header_value(header.value.expose_secret())?,
        );
    }
    request = request.headers(headers);
    if input.method != "GET"
        && let Some(body) = &input.body
    {
        let body = serde_json::to_vec(body)
            .map_err(|error| Error::validation(format!("serialize request body: {error}")))?;
        request = request.header(
            reqwest::header::CONTENT_TYPE,
            input.content_type.as_deref().unwrap_or("application/json"),
        );
        request = request.body(body);
    }
    let response = request
        .send()
        .await
        .map_err(opsgate_infra::http::map_send_error)?;
    Ok(TargetResponseHead {
        status: response.status(),
        headers: response.headers().clone(),
        response,
    })
}

struct TargetResponseHead {
    status: reqwest::StatusCode,
    headers: HeaderMap,
    response: reqwest::Response,
}

pub(super) fn build_target_url(
    target: &CredentialTarget,
    input: &NormalizedApiCallInput,
) -> Result<url::Url> {
    let CredentialTarget::Http { origin, base_path } = target else {
        return Err(Error::validation("credential target is not HTTP"));
    };
    let mut url = url::Url::parse(origin)
        .map_err(|error| Error::validation(format!("credential origin URL: {error}")))?;
    let path = join_base_path(base_path, &input.request_path);
    url.set_path(&path);
    url.set_query(None);
    if !input.query.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in &input.query {
            pairs.append_pair(key, value);
        }
    }
    Ok(url)
}

fn join_base_path(base_path: &str, request_path: &str) -> String {
    let base = base_path.trim_end_matches('/');
    if base.is_empty() {
        request_path.to_owned()
    } else {
        format!("{base}{request_path}")
    }
}

fn header_name(name: &str) -> Result<HeaderName> {
    HeaderName::from_bytes(name.as_bytes())
        .map_err(|_error| Error::validation("invalid header name"))
}

fn header_value(value: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(value).map_err(|_error| Error::validation("invalid header value"))
}

async fn read_capped(
    response: &mut reqwest::Response,
    limit: usize,
) -> Result<(Vec<u8>, usize, bool)> {
    if let Some(content_length) = response.content_length()
        && content_length > u64::try_from(limit).unwrap_or(u64::MAX)
    {
        return Ok((
            Vec::new(),
            usize::try_from(content_length).unwrap_or(usize::MAX),
            true,
        ));
    }

    let mut out = Vec::new();
    let mut original = 0_usize;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_error| Error::internal("read target response failed"))?
    {
        let next_original = original.saturating_add(chunk.len());
        if out.len() < limit {
            let remaining = limit - out.len();
            let take = remaining.min(chunk.len());
            let part = chunk
                .get(..take)
                .ok_or_else(|| Error::internal("response chunk slice out of range"))?;
            out.extend_from_slice(part);
        }
        if next_original > limit {
            return Ok((out, limit.saturating_add(1), true));
        }
        original = next_original;
    }
    Ok((out, original, false))
}

fn response_content_type_is_json(headers: &HeaderMap) -> bool {
    headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("json"))
}

fn filtered_response_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for name in [
        "cache-control",
        "content-type",
        "etag",
        "last-modified",
        "resourceversion",
    ] {
        if let Some(value) = headers.get(name).and_then(|value| value.to_str().ok()) {
            out.insert(name.to_owned(), value.to_owned());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use opsgate_core::Result;
    use opsgate_model::credential::CredentialTarget;

    use super::super::input::{ApiCallInput, normalize_input};
    use super::*;

    fn base_input() -> ApiCallInput {
        ApiCallInput {
            alias: "prod".to_owned(),
            purpose: "Check pod phases".to_owned(),
            method: "GET".to_owned(),
            request_path: "/api/v1/pods".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: None,
            content_type: String::new(),
            jsonpath: Vec::new(),
            max_bytes: Some(4096),
        }
    }

    #[test]
    fn runtime_target_preflight_blocks_private_ip_literal_urls() -> Result<()> {
        let input = normalize_input(ApiCallInput {
            request_path: "/status".to_owned(),
            ..base_input()
        })?;
        for origin in ["https://127.0.0.1", "https://[::ffff:127.0.0.1]"] {
            let target = CredentialTarget::Http {
                origin: origin.to_owned(),
                base_path: "/".to_owned(),
            };
            let url = build_target_url(&target, &input)?;
            let err = opsgate_infra::http::ensure_url_allowed(&url, true, false)
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default();
            assert!(err.contains("private/link-local/loopback"));
        }
        Ok(())
    }

    #[test]
    fn target_url_discards_origin_path_and_query() -> Result<()> {
        let input = normalize_input(ApiCallInput {
            request_path: "/v1/pods".to_owned(),
            query: BTreeMap::from([
                ("labelSelector".to_owned(), "app=web".to_owned()),
                ("limit".to_owned(), "10".to_owned()),
            ]),
            ..base_input()
        })?;
        let target = CredentialTarget::Http {
            origin: "https://api.example.test/leaked/path?token=must-not-survive".to_owned(),
            base_path: "/cluster-a/".to_owned(),
        };

        let url = build_target_url(&target, &input)?;

        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("api.example.test"));
        assert_eq!(url.path(), "/cluster-a/v1/pods");
        assert_eq!(url.query(), Some("labelSelector=app%3Dweb&limit=10"));
        assert!(!url.as_str().contains("must-not-survive"));
        Ok(())
    }

    #[test]
    fn target_url_allows_empty_hidden_base_path() -> Result<()> {
        let input = normalize_input(ApiCallInput {
            request_path: "/readyz".to_owned(),
            ..base_input()
        })?;
        let target = CredentialTarget::Http {
            origin: "https://api.example.test".to_owned(),
            base_path: String::new(),
        };

        let url = build_target_url(&target, &input)?;

        assert_eq!(url.as_str(), "https://api.example.test/readyz");
        Ok(())
    }

    #[test]
    fn response_content_type_accepts_only_json_media_types() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert!(!response_content_type_is_json(&headers));

        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("text/plain"),
        );
        assert!(!response_content_type_is_json(&headers));

        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/problem+json"),
        );
        assert!(response_content_type_is_json(&headers));
    }

    #[test]
    fn filtered_response_headers_keeps_only_safe_target_metadata() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            reqwest::header::CACHE_CONTROL,
            reqwest::header::HeaderValue::from_static("no-cache"),
        );
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_static("Bearer secret"),
        );
        headers.insert(
            reqwest::header::SET_COOKIE,
            reqwest::header::HeaderValue::from_static("sid=secret"),
        );
        headers.insert(
            reqwest::header::HeaderName::from_static("resourceversion"),
            reqwest::header::HeaderValue::from_static("123"),
        );

        let filtered = filtered_response_headers(&headers);

        assert_eq!(
            filtered.get("content-type"),
            Some(&"application/json".to_owned())
        );
        assert_eq!(filtered.get("cache-control"), Some(&"no-cache".to_owned()));
        assert_eq!(filtered.get("resourceversion"), Some(&"123".to_owned()));
        assert!(!filtered.contains_key("authorization"));
        assert!(!filtered.contains_key("set-cookie"));
    }

    #[test]
    fn target_request_error_keeps_user_safe_recording_fields() {
        let error = Error::user_safe(
            "target_timeout",
            "Target request timed out before receiving a response.",
            Some("Check target availability."),
        );

        let execution = CallExecutionError::target_request(error);

        assert_eq!(execution.kind, "target_timeout");
        assert_eq!(
            execution.message,
            "Target request timed out before receiving a response."
        );
    }

    #[test]
    fn target_request_error_falls_back_for_internal_recording() {
        let execution = CallExecutionError::target_request(Error::internal("secret target URL"));

        assert_eq!(execution.kind, reason::TARGET_REQUEST_FAILED);
        assert_eq!(execution.message, "target request failed");
    }

    #[test]
    fn target_url_joins_hidden_base_path() -> Result<()> {
        let input = normalize_input(ApiCallInput {
            request_path: "/v1/pods".to_owned(),
            query: BTreeMap::from([("label".to_owned(), "app=web".to_owned())]),
            ..base_input()
        })?;
        let target = CredentialTarget::Http {
            origin: "https://api.example.test".to_owned(),
            base_path: "/base".to_owned(),
        };
        let url = build_target_url(&target, &input)?;
        assert_eq!(
            url.as_str(),
            "https://api.example.test/base/v1/pods?label=app%3Dweb"
        );

        let target = CredentialTarget::Http {
            origin: "https://api.example.test".to_owned(),
            base_path: "/".to_owned(),
        };
        let url = build_target_url(&target, &input)?;
        assert_eq!(
            url.as_str(),
            "https://api.example.test/v1/pods?label=app%3Dweb"
        );
        Ok(())
    }
}

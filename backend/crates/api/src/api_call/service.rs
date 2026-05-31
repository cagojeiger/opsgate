use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use opsgate_core::llm_output::{More, build_json_output, validate_json_paths};
use opsgate_core::validation::{
    reject_crlf, trim_required, validate_count, validate_http_header_name,
    validate_http_header_value, validate_http_path, validate_max_bytes, validate_purpose,
    validate_text_len,
};
use opsgate_core::{Error, Result};
use opsgate_db::{ApiCallHistoryParams, ApiCallHistoryRepo, AuditRepo, CredentialRepo};
use opsgate_domain::Caller;
use opsgate_domain::credential::{Credential, CredentialCategory, CredentialTarget, SecretHeader};
use opsgate_domain::credential::{contains_fold, header_blocked, request_path_matches_prefix};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::runtime::reason;
use crate::credential::secret;
use crate::credential::snapshot::CredentialSnapshot;
use crate::target::http::TargetHttpClients;

const DEFAULT_METHOD: &str = "GET";
const DEFAULT_MAX_BYTES: usize = 4096;
const MIN_MAX_BYTES: usize = 256;
const MAX_MAX_BYTES: usize = 1024 * 1024;
const MAX_QUERY_KEYS: usize = 32;
const MAX_QUERY_KEY_LEN: usize = 128;
const MAX_QUERY_VALUE_LEN: usize = 4096;
const MAX_HEADERS: usize = 16;
const MAX_HEADER_NAME_LEN: usize = 128;
const MAX_HEADER_VALUE_LEN: usize = 1024;
const TARGET_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub(crate) struct ApiCallService {
    credentials: CredentialRepo,
    history: ApiCallHistoryRepo,
    audit: AuditRepo,
    sealer: opsgate_core::crypto::Sealer,
    target_clients: TargetHttpClients,
}

impl ApiCallService {
    pub fn new(
        credentials: CredentialRepo,
        history: ApiCallHistoryRepo,
        audit: AuditRepo,
        sealer: opsgate_core::crypto::Sealer,
    ) -> Result<Self> {
        Ok(Self {
            credentials,
            history,
            audit,
            sealer,
            target_clients: TargetHttpClients::new(TARGET_TIMEOUT)?,
        })
    }

    pub async fn call(&self, caller: &Caller, input: ApiCallInput) -> Result<ApiCallOutput> {
        // Sanitize the raw alias up front: on the bad-input path it is the only
        // request field we record, and it has not been validated yet.
        let raw_alias = crate::audit::safe::message(&input.alias);
        let input = match normalize_input(input) {
            Ok(input) => input,
            Err(error) => {
                self.record_bad_input(caller, &raw_alias, &error).await;
                return Err(error);
            }
        };
        let mut recorder = CallRecorder::new(&self.history, &self.audit, caller, &input);

        let row = match self
            .credentials
            .find_credential_secret_by_alias(caller.user.id, &input.alias)
            .await?
        {
            Some(row) => row,
            None => {
                recorder
                    .denied(reason::CREDENTIAL_NOT_FOUND, "credential not found")
                    .await;
                return Err(Error::not_found("credential not found"));
            }
        };
        let material = row.into_credential()?;
        let credential = material.credential;
        let secret_ciphertext = material.secret_ciphertext;
        let tls_ca = material.tls_ca;
        recorder.set_credential(&credential);

        if credential.category != CredentialCategory::Http {
            recorder
                .denied(
                    reason::WRONG_CREDENTIAL_CATEGORY,
                    "credential is not category=http",
                )
                .await;
            return Err(Error::validation(reason::WRONG_CREDENTIAL_CATEGORY));
        }
        if let Err(error) = validate_policy_boundary(&credential, &input) {
            recorder
                .denied(reason::POLICY_DENIED, &error.to_string())
                .await;
            return Err(error);
        }

        let secret_ciphertext = match secret_ciphertext {
            Some(secret_ciphertext) => secret_ciphertext,
            None => {
                recorder
                    .err(reason::SECRET_DESTROYED, "credential secret is destroyed")
                    .await;
                return Err(Error::validation("credential secret is destroyed"));
            }
        };
        let secret =
            match secret::open_http_headers(&self.sealer, &credential.alias, &secret_ciphertext) {
                Ok(secret) => secret,
                Err(error) => {
                    recorder
                        .err(reason::SECRET_OPEN_FAILED, "credential secret open failed")
                        .await;
                    return Err(error);
                }
            };
        if let Err(error) = validate_no_secret_header_override(&secret, &input) {
            recorder
                .denied(reason::POLICY_DENIED, &error.to_string())
                .await;
            return Err(error);
        }

        let url = match build_target_url(&credential.target, &input) {
            Ok(url) => url,
            Err(error) => {
                recorder
                    .err(reason::TARGET_URL_FAILED, "target URL build failed")
                    .await;
                return Err(error);
            }
        };
        let started = Instant::now();
        let mut response = match self
            .send_target(&credential, tls_ca.as_deref(), &url, &input, &secret)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                recorder
                    .err(reason::TARGET_REQUEST_FAILED, "target request failed")
                    .await;
                return Err(error);
            }
        };
        let status_code = i32::from(response.status.as_u16());
        let headers = filtered_response_headers(&response.headers);
        if !response_content_type_is_json(&response.headers) {
            recorder
                .err(reason::TARGET_NOT_JSON, "target response is not JSON")
                .await;
            return Err(Error::validation("target response is not JSON"));
        }
        let (body, original_bytes, transport_truncated) =
            match read_capped(&mut response.response, MAX_MAX_BYTES).await {
                Ok(parts) => parts,
                Err(error) => {
                    recorder
                        .err(reason::TARGET_READ_FAILED, "read target response failed")
                        .await;
                    return Err(error);
                }
            };
        let latency_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);

        let shaped = match build_json_output(
            &body,
            opsgate_core::llm_output::JsonOutputOptions {
                max_bytes: input.max_bytes,
                max_allowed_bytes: MAX_MAX_BYTES,
                json_paths: input.jsonpath.clone(),
                transport_truncated,
                original_bytes: Some(original_bytes),
            },
        ) {
            Ok(shaped) => shaped,
            Err(error) => {
                recorder
                    .err(reason::OUTPUT_BUILD_FAILED, "output build failed")
                    .await;
                return Err(error);
            }
        };
        let output = ApiCallOutput {
            status_code,
            headers,
            body: shaped.body,
            truncated: shaped.truncated,
            original_bytes: shaped.original_bytes,
            returned_bytes: shaped.returned_bytes,
            latency_ms,
            more: shaped.more,
        };
        recorder.ok(&output).await;
        Ok(output)
    }

    /// Record an input-validation rejection (before a normalized input exists).
    /// Mirrors the per-tool denial stream so input-shaped abuse is still audited.
    async fn record_bad_input(&self, caller: &Caller, alias: &str, error: &Error) {
        self.record_pre_input_denial(caller, alias, reason::BAD_INPUT, error)
            .await;
    }

    async fn record_pre_input_denial(
        &self,
        caller: &Caller,
        alias: &str,
        reason: &str,
        error: &Error,
    ) {
        crate::audit::append_event(
            &self.audit,
            pre_input_denial_audit_event(caller, alias, reason),
            "api.call.audit_failed",
        )
        .await;
        if let Err(error) = self
            .history
            .insert(pre_input_denial_history_params(
                caller, alias, reason, error,
            ))
            .await
        {
            tracing::error!(event = "api.call.history_failed", detail = %error);
        }
    }

    async fn send_target(
        &self,
        credential: &Credential,
        tls_ca: Option<&[u8]>,
        url: &url::Url,
        input: &NormalizedApiCallInput,
        secret: &[SecretHeader],
    ) -> Result<TargetResponseHead> {
        let method = reqwest::Method::from_bytes(input.method.as_bytes())
            .map_err(|error| Error::validation(format!("invalid method: {error}")))?;
        let mut request = self.target_clients.request_for(
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
            .map_err(crate::target::http::map_send_error)?;
        Ok(TargetResponseHead {
            status: response.status(),
            headers: response.headers().clone(),
            response,
        })
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct ApiCallInput {
    pub alias: String,
    pub purpose: String,
    #[serde(default)]
    pub method: String,
    pub request_path: String,
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    #[schemars(schema_with = "opsgate_core::schema::optional_json_value_schema")]
    pub body: Option<Value>,
    #[serde(default)]
    pub content_type: String,
    #[serde(default)]
    pub jsonpath: Vec<String>,
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub(crate) struct ApiCallOutput {
    pub status_code: i32,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[schemars(schema_with = "opsgate_core::schema::json_value_schema")]
    pub body: Value,
    pub truncated: bool,
    pub original_bytes: usize,
    pub returned_bytes: usize,
    pub latency_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub more: Option<More>,
}

#[derive(Debug, Clone)]
struct NormalizedApiCallInput {
    alias: String,
    purpose: String,
    method: String,
    request_path: String,
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    body: Option<Value>,
    content_type: Option<String>,
    jsonpath: Vec<String>,
    max_bytes: usize,
}

struct TargetResponseHead {
    status: reqwest::StatusCode,
    headers: HeaderMap,
    response: reqwest::Response,
}

fn normalize_input(input: ApiCallInput) -> Result<NormalizedApiCallInput> {
    let alias = opsgate_core::validation::trim_required("alias", &input.alias)?;
    let purpose = validate_purpose(&input.purpose)?;
    let method = if input.method.trim().is_empty() {
        DEFAULT_METHOD.to_owned()
    } else {
        input.method.trim().to_ascii_uppercase()
    };
    if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
        return Err(Error::validation("unsupported method"));
    }
    if method == "GET" && input.body.is_some() {
        return Err(Error::validation("GET must not carry a body"));
    }
    let request_path = validate_http_path(&input.request_path)?;
    let max_bytes = validate_max_bytes(
        input.max_bytes,
        DEFAULT_MAX_BYTES,
        MIN_MAX_BYTES,
        MAX_MAX_BYTES,
    )?;
    validate_json_paths(&input.jsonpath)?;
    let query = normalize_query(input.query)?;
    validate_count("headers", input.headers.len(), MAX_HEADERS)?;
    let mut headers = BTreeMap::new();
    for (name, value) in input.headers {
        let name = validate_http_header_name(&name, MAX_HEADER_NAME_LEN)?;
        let value = validate_http_header_value(&value, MAX_HEADER_VALUE_LEN)?;
        if name.eq_ignore_ascii_case("accept") && !value.to_ascii_lowercase().contains("json") {
            return Err(Error::validation("header Accept must request JSON"));
        }
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_error| Error::validation("invalid header name"))?
                .to_string(),
            value,
        );
    }
    let content_type = if input.content_type.trim().is_empty() {
        None
    } else {
        Some(input.content_type.trim().to_owned())
    };
    if let Some(content_type) = &content_type {
        validate_http_header_value(content_type, MAX_HEADER_VALUE_LEN)?;
        if input.body.is_some() && !content_type.to_ascii_lowercase().contains("json") {
            return Err(Error::validation("content_type must describe JSON"));
        }
    }
    let mut jsonpath = input.jsonpath;
    for path in &mut jsonpath {
        *path = path.trim().to_owned();
    }
    Ok(NormalizedApiCallInput {
        alias,
        purpose,
        method,
        request_path,
        query,
        headers,
        body: input.body,
        content_type,
        jsonpath,
        max_bytes,
    })
}

fn normalize_query(query: BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
    validate_count("query", query.len(), MAX_QUERY_KEYS)?;
    let mut normalized = BTreeMap::new();
    for (key, value) in query {
        let key = trim_required("query key", &key)?;
        reject_crlf("query key", &key)?;
        validate_text_len("query key", &key, 1, MAX_QUERY_KEY_LEN)?;
        if key.contains('\0') {
            return Err(Error::validation("query key must not contain NUL"));
        }
        reject_crlf("query value", &value)?;
        validate_text_len("query value", &value, 0, MAX_QUERY_VALUE_LEN)?;
        if value.contains('\0') {
            return Err(Error::validation("query value must not contain NUL"));
        }
        normalized.insert(key, value);
    }
    Ok(normalized)
}

fn validate_policy_boundary(credential: &Credential, input: &NormalizedApiCallInput) -> Result<()> {
    if !contains_fold(&credential.policy.allowed_methods, &input.method) {
        return Err(Error::validation("method not allowed by credential policy"));
    }
    if !credential
        .policy
        .allowed_request_path_prefixes
        .iter()
        .any(|prefix| request_path_matches_prefix(&input.request_path, prefix))
    {
        return Err(Error::validation(
            "request_path not allowed by credential policy",
        ));
    }
    for key in input.query.keys() {
        if contains_fold(&credential.policy.denied_query_keys, key) {
            return Err(Error::validation("query key denied by credential policy"));
        }
    }
    for name in input.headers.keys() {
        if header_blocked(name) {
            return Err(Error::validation("blocked request header"));
        }
        if !contains_fold(&credential.policy.allowed_request_headers, name) {
            return Err(Error::validation(
                "request header not allowed by credential policy",
            ));
        }
    }
    Ok(())
}

fn validate_no_secret_header_override(
    secret: &[SecretHeader],
    input: &NormalizedApiCallInput,
) -> Result<()> {
    for header in secret {
        if input
            .headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case(&header.name))
        {
            return Err(Error::validation(
                "caller header cannot override sealed secret header",
            ));
        }
    }
    Ok(())
}

fn build_target_url(target: &CredentialTarget, input: &NormalizedApiCallInput) -> Result<url::Url> {
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

struct CallRecorder<'a> {
    history: &'a ApiCallHistoryRepo,
    audit: &'a AuditRepo,
    caller: &'a Caller,
    input: &'a NormalizedApiCallInput,
    credential: Option<CredentialSnapshot>,
}

impl<'a> CallRecorder<'a> {
    fn new(
        history: &'a ApiCallHistoryRepo,
        audit: &'a AuditRepo,
        caller: &'a Caller,
        input: &'a NormalizedApiCallInput,
    ) -> Self {
        Self {
            history,
            audit,
            caller,
            input,
            credential: None,
        }
    }

    fn set_credential(&mut self, credential: &Credential) {
        self.credential = Some(CredentialSnapshot::from(credential));
    }

    async fn denied(&self, kind: &str, message: &str) {
        self.record("denied", Some(kind), Some(message), None).await;
    }

    async fn err(&self, kind: &str, message: &str) {
        self.record("error", Some(kind), Some(message), None).await;
    }

    async fn ok(&self, output: &ApiCallOutput) {
        self.record("ok", None, None, Some(output)).await;
    }

    async fn record(
        &self,
        outcome: &str,
        error_kind: Option<&str>,
        error_message: Option<&str>,
        output: Option<&ApiCallOutput>,
    ) {
        self.record_audit(outcome, error_kind, output).await;
        let credential = self.credential.as_ref();
        let params = ApiCallHistoryParams {
            owner_user_id: credential
                .map(|credential| credential.owner_user_id)
                .or(Some(self.caller.user.id)),
            actor_user_id: Some(self.caller.user.id),
            channel: crate::audit::runtime::history_channel_str(self.caller.channel).to_owned(),
            request_id: self.caller.request_id.clone(),
            credential_id: credential.map(|credential| credential.id),
            credential_alias: credential
                .map(|credential| credential.alias.clone())
                .unwrap_or_else(|| self.input.alias.clone()),
            credential_category: credential
                .map(|credential| credential.category.as_str().to_owned())
                .unwrap_or_default(),
            credential_provider: credential
                .map(|credential| credential.provider.clone())
                .unwrap_or_default(),
            credential_env: credential
                .map(|credential| credential.env.clone())
                .unwrap_or_default(),
            method: self.input.method.clone(),
            request_path: self.input.request_path.clone(),
            query_keys: serde_json::json!(self.input.query.keys().cloned().collect::<Vec<_>>()),
            request_header_keys: serde_json::json!(
                self.input.headers.keys().cloned().collect::<Vec<_>>()
            ),
            projection_keys: serde_json::json!(self.input.jsonpath),
            max_bytes: i32::try_from(self.input.max_bytes).unwrap_or(i32::MAX),
            purpose: Some(self.input.purpose.clone()),
            outcome: outcome.to_owned(),
            status_code: output.map(|output| output.status_code),
            latency_ms: output.map(|output| output.latency_ms),
            original_bytes: output
                .map(|output| i32::try_from(output.original_bytes).unwrap_or(i32::MAX)),
            returned_bytes: output
                .map(|output| i32::try_from(output.returned_bytes).unwrap_or(i32::MAX)),
            truncated: output.is_some_and(|output| output.truncated),
            error_kind: error_kind.map(str::to_owned),
            error_message_safe: error_message.map(crate::audit::safe::message),
        };
        if let Err(error) = self.history.insert(params).await {
            tracing::error!(event = "api.call.history_failed", detail = %error);
        }
    }

    async fn record_audit(
        &self,
        outcome: &str,
        error_kind: Option<&str>,
        output: Option<&ApiCallOutput>,
    ) {
        let credential = self.credential.as_ref();
        crate::audit::runtime::append_tool_event(crate::audit::runtime::ToolEventRecord {
            audit: self.audit,
            caller: self.caller,
            tool: "api.call",
            outcome,
            credential,
            fallback_alias: &self.input.alias,
            purpose: Some(self.input.purpose.clone()),
            detail: audit_detail(self.input, credential, outcome, error_kind, output),
            failure_event: "api.call.audit_failed",
        })
        .await;
    }
}

fn audit_detail(
    input: &NormalizedApiCallInput,
    credential: Option<&CredentialSnapshot>,
    outcome: &str,
    error_kind: Option<&str>,
    output: Option<&ApiCallOutput>,
) -> Value {
    let mut detail = serde_json::Map::new();
    detail.insert("schema_version".to_owned(), serde_json::json!(1));
    detail.insert("method".to_owned(), serde_json::json!(input.method));
    detail.insert(
        "request_path".to_owned(),
        serde_json::json!(input.request_path),
    );
    detail.insert("purpose".to_owned(), serde_json::json!(input.purpose));
    let query_keys = input.query.keys().cloned().collect::<Vec<_>>();
    if !query_keys.is_empty() {
        detail.insert("query_keys".to_owned(), serde_json::json!(query_keys));
    }
    let header_keys = input.headers.keys().cloned().collect::<Vec<_>>();
    if !header_keys.is_empty() {
        detail.insert(
            "request_header_keys".to_owned(),
            serde_json::json!(header_keys),
        );
    }
    if !input.jsonpath.is_empty() {
        detail.insert("jsonpath".to_owned(), serde_json::json!(input.jsonpath));
    }
    if let Some(credential) = credential {
        crate::audit::runtime::insert_credential_detail(
            &mut detail,
            credential.category.as_str(),
            &credential.provider,
            &credential.env,
        );
    }
    crate::audit::runtime::insert_reason_detail(&mut detail, outcome, error_kind);
    if let Some(output) = output {
        detail.insert(
            "status_code".to_owned(),
            serde_json::json!(output.status_code),
        );
        detail.insert(
            "latency_ms".to_owned(),
            serde_json::json!(output.latency_ms),
        );
        detail.insert(
            "response_bytes".to_owned(),
            serde_json::json!(output.original_bytes),
        );
        detail.insert(
            "returned_bytes".to_owned(),
            serde_json::json!(output.returned_bytes),
        );
        if output.truncated {
            detail.insert("truncated".to_owned(), serde_json::json!(true));
        }
    }
    Value::Object(detail)
}

/// Audit row for a pre-normalization denial. Records only the channel, the
/// (pre-sanitized) alias, and denial reason — never the raw input.
fn pre_input_denial_audit_event(
    caller: &Caller,
    alias: &str,
    reason: &str,
) -> crate::audit::AuditEvent {
    crate::audit::runtime::pre_input_denial_event(caller, "api.call", alias, reason, None)
}

/// History row for a pre-normalization denial. `error_message_safe` carries the
/// (value-free, CR/LF-stripped) validation reason; no normalized fields exist.
fn pre_input_denial_history_params(
    caller: &Caller,
    alias: &str,
    reason: &str,
    error: &Error,
) -> ApiCallHistoryParams {
    ApiCallHistoryParams {
        owner_user_id: Some(caller.user.id),
        actor_user_id: Some(caller.user.id),
        channel: crate::audit::runtime::history_channel_str(caller.channel).to_owned(),
        request_id: caller.request_id.clone(),
        credential_id: None,
        credential_alias: alias.to_owned(),
        credential_category: String::new(),
        credential_provider: String::new(),
        credential_env: String::new(),
        method: String::new(),
        request_path: String::new(),
        query_keys: serde_json::json!([]),
        request_header_keys: serde_json::json!([]),
        projection_keys: serde_json::json!([]),
        max_bytes: 0,
        purpose: None,
        outcome: "denied".to_owned(),
        status_code: None,
        latency_ms: None,
        original_bytes: None,
        returned_bytes: None,
        truncated: false,
        error_kind: Some(reason.to_owned()),
        error_message_safe: Some(crate::audit::safe::message(&error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use opsgate_domain::credential::{CredentialPolicy, CredentialTarget};
    use secrecy::SecretString;
    use uuid::Uuid;

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

    fn http_credential(policy: CredentialPolicy) -> Credential {
        let now = Utc::now();
        Credential {
            id: Uuid::nil(),
            owner_user_id: Uuid::nil(),
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod".to_owned(),
            target: CredentialTarget::Http {
                origin: "https://api.example.test".to_owned(),
                base_path: "/".to_owned(),
            },
            description: String::new(),
            env: "prod".to_owned(),
            tags: Vec::new(),
            policy,
            allow_private_network: false,
            allow_insecure_transport: false,
            has_tls_ca: false,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn input_validation_matches_docs_boundary() {
        assert!(
            normalize_input(ApiCallInput {
                jsonpath: vec!["$.items[*].metadata.name".to_owned()],
                ..base_input()
            })
            .is_ok()
        );
    }

    #[test]
    fn input_validation_rejects_docs_p0_cases() {
        let mut input = base_input();
        input.purpose = "bad\nsecret-token".to_owned();
        assert!(normalize_input(input.clone()).is_err());
        input.purpose = "Check pod phases".to_owned();
        input.request_path = "/api/../secret".to_owned();
        assert!(normalize_input(input.clone()).is_err());
        input.request_path = "/api/v1/pods".to_owned();
        input.jsonpath = vec!["$..metadata.name".to_owned()];
        assert!(normalize_input(input.clone()).is_err());
        input.jsonpath = Vec::new();
        input
            .headers
            .insert("Accept".to_owned(), "text/plain".to_owned());
        assert!(normalize_input(input).is_err());
    }

    #[test]
    fn input_validation_rejects_query_boundary_violations() {
        let too_many = (0..=MAX_QUERY_KEYS)
            .map(|index| (format!("k{index}"), "v".to_owned()))
            .collect::<BTreeMap<_, _>>();
        assert!(
            normalize_input(ApiCallInput {
                query: too_many,
                ..base_input()
            })
            .is_err()
        );

        assert!(
            normalize_input(ApiCallInput {
                query: BTreeMap::from([("".to_owned(), "value".to_owned())]),
                ..base_input()
            })
            .is_err()
        );
        assert!(
            normalize_input(ApiCallInput {
                query: BTreeMap::from([("token".to_owned(), "secret\nleak".to_owned())]),
                ..base_input()
            })
            .is_err()
        );
        assert!(
            normalize_input(ApiCallInput {
                query: BTreeMap::from([("k".repeat(MAX_QUERY_KEY_LEN + 1), "v".to_owned())]),
                ..base_input()
            })
            .is_err()
        );
        assert!(
            normalize_input(ApiCallInput {
                query: BTreeMap::from([("k".to_owned(), "v".repeat(MAX_QUERY_VALUE_LEN + 1))]),
                ..base_input()
            })
            .is_err()
        );
    }

    #[test]
    fn input_validation_rejects_non_json_content_type_with_body() {
        let input = ApiCallInput {
            method: "POST".to_owned(),
            body: Some(serde_json::json!({"kind": "Pod"})),
            content_type: "text/plain".to_owned(),
            ..base_input()
        };
        assert!(normalize_input(input).is_err());
    }

    #[test]
    fn policy_boundary_rejects_docs_denials() -> Result<()> {
        let credential = http_credential(CredentialPolicy {
            allowed_methods: vec!["GET".to_owned()],
            allowed_request_path_prefixes: vec!["/api".to_owned()],
            denied_query_keys: vec!["token".to_owned()],
            allowed_request_headers: vec!["Accept".to_owned()],
            ..CredentialPolicy::default()
        });
        let input = normalize_input(base_input())?;
        assert!(validate_policy_boundary(&credential, &input).is_ok());

        let mut denied_query = base_input();
        denied_query
            .query
            .insert("token".to_owned(), "secret-value".to_owned());
        let denied_query = normalize_input(denied_query)?;
        assert!(validate_policy_boundary(&credential, &denied_query).is_err());

        let disallowed_header = normalize_input(ApiCallInput {
            headers: BTreeMap::from([("X-Trace-Id".to_owned(), "abc".to_owned())]),
            ..base_input()
        })?;
        assert!(validate_policy_boundary(&credential, &disallowed_header).is_err());

        let blocked_header = normalize_input(ApiCallInput {
            headers: BTreeMap::from([("Host".to_owned(), "example.test".to_owned())]),
            ..base_input()
        })?;
        assert!(validate_policy_boundary(&credential, &blocked_header).is_err());

        let method_denied = normalize_input(ApiCallInput {
            method: "DELETE".to_owned(),
            ..base_input()
        })?;
        assert!(validate_policy_boundary(&credential, &method_denied).is_err());

        let path_denied = normalize_input(ApiCallInput {
            request_path: "/other".to_owned(),
            ..base_input()
        })?;
        assert!(validate_policy_boundary(&credential, &path_denied).is_err());
        Ok(())
    }

    #[test]
    fn policy_boundary_rejects_secret_header_override() -> Result<()> {
        let input = normalize_input(ApiCallInput {
            headers: BTreeMap::from([("X-Api-Key".to_owned(), "caller-value".to_owned())]),
            ..base_input()
        })?;
        let secret = vec![SecretHeader {
            name: "x-api-key".to_owned(),
            value: SecretString::from("sealed-value"),
        }];
        assert!(validate_no_secret_header_override(&secret, &input).is_err());
        Ok(())
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
            let err = crate::target::http::ensure_url_allowed(&url, true, false)
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default();
            assert!(err.contains("private/link-local/loopback"));
        }
        Ok(())
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

    #[test]
    fn history_message_is_bounded_and_single_line() {
        let message = format!("secret\r\n{}", "x".repeat(600));
        let safe = crate::audit::safe::message(&message);
        assert!(!safe.contains(['\r', '\n']));
        assert_eq!(safe.chars().count(), 512);
    }

    #[test]
    fn audit_detail_stores_only_safe_request_facts() -> Result<()> {
        let input = normalize_input(ApiCallInput {
            method: "POST".to_owned(),
            query: BTreeMap::from([("token".to_owned(), "query-secret".to_owned())]),
            headers: BTreeMap::from([("Accept".to_owned(), "application/json".to_owned())]),
            body: Some(serde_json::json!({"secret": "body-secret"})),
            jsonpath: vec!["$.items[*].metadata.name".to_owned()],
            ..base_input()
        })?;
        let credential = CredentialSnapshot::from(&http_credential(CredentialPolicy::default()));
        let detail = audit_detail(
            &input,
            Some(&credential),
            "denied",
            Some(reason::POLICY_DENIED),
            None,
        );
        let serialized = detail.to_string();
        assert!(serialized.contains("query_keys"));
        assert!(serialized.contains("request_header_keys"));
        assert!(serialized.contains("denial_reason"));
        assert!(!serialized.contains("query-secret"));
        assert!(!serialized.contains("body-secret"));
        assert!(!serialized.contains("api.example.test"));
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("\"reason\""));
        Ok(())
    }

    #[test]
    fn audit_detail_uses_top_level_truncated_flag() -> Result<()> {
        let input = normalize_input(base_input())?;
        let output = ApiCallOutput {
            status_code: 200,
            headers: BTreeMap::new(),
            body: Value::Null,
            truncated: true,
            original_bytes: MAX_MAX_BYTES + 1,
            returned_bytes: 0,
            latency_ms: 12,
            more: None,
        };

        let detail = audit_detail(&input, None, "ok", None, Some(&output));
        assert_eq!(detail.get("truncated"), Some(&serde_json::json!(true)));
        Ok(())
    }

    fn test_caller() -> opsgate_domain::Caller {
        let now = Utc::now();
        opsgate_domain::Caller {
            user: opsgate_domain::User {
                id: uuid::Uuid::nil(),
                sub: "sub".to_owned(),
                email: "user@example.test".to_owned(),
                display_name: "User".to_owned(),
                is_active: true,
                created_at: now,
                updated_at: now,
            },
            channel: opsgate_domain::Channel::Mcp,
            request_id: None,
            remote_ip: None,
            user_agent: None,
        }
    }

    #[test]
    fn bad_input_denial_is_recorded_safely() {
        let caller = test_caller();
        let error = Error::validation("purpose must be at least 8 characters");

        let history = pre_input_denial_history_params(&caller, "prod", reason::BAD_INPUT, &error);
        assert_eq!(history.outcome, "denied");
        assert_eq!(history.error_kind.as_deref(), Some(reason::BAD_INPUT));
        assert!(history.purpose.is_none());
        assert_eq!(history.credential_alias, "prod");
        assert!(history.method.is_empty());
        assert_eq!(history.status_code, None);

        let audit = pre_input_denial_audit_event(&caller, "prod", reason::BAD_INPUT).into_params();
        assert_eq!(audit.outcome, "denied");
        assert_eq!(audit.action, "mcp.api.call");
        assert!(audit.purpose.is_none());
        assert_eq!(
            audit.detail.get("denial_reason"),
            Some(&serde_json::json!(reason::BAD_INPUT))
        );
    }
}

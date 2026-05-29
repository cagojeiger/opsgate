use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use opsgate_core::llm_output::{More, build_json_output, validate_json_paths};
use opsgate_core::net::ssrf::is_blocked_target_ip;
use opsgate_core::validation::{
    validate_count, validate_http_header_name, validate_http_header_value, validate_http_path,
    validate_max_bytes, validate_purpose,
};
use opsgate_core::{Error, Result};
use opsgate_db::{
    ApiCallHistoryParams, ApiCallHistoryRepo, AuditLogParams, AuditRepo, CredentialRepo,
};
use opsgate_domain::credential::{Credential, CredentialCategory, SecretHeader};
use opsgate_domain::credential::{contains_fold, header_blocked};
use opsgate_domain::{Caller, Channel};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::target::TargetHttpClients;

const DEFAULT_METHOD: &str = "GET";
const DEFAULT_MAX_BYTES: usize = 4096;
const MIN_MAX_BYTES: usize = 256;
const MAX_MAX_BYTES: usize = 1024 * 1024;
const MAX_HEADERS: usize = 16;
const MAX_HEADER_NAME_LEN: usize = 128;
const MAX_HEADER_VALUE_LEN: usize = 1024;
const SECRET_DOMAIN: &str = "credentials";
const TARGET_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct ApiCallService {
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
        http: reqwest::Client,
    ) -> Self {
        Self {
            credentials,
            history,
            audit,
            sealer,
            target_clients: TargetHttpClients::new(http, TARGET_TIMEOUT),
        }
    }

    pub async fn call(&self, caller: &Caller, input: ApiCallInput) -> Result<ApiCallOutput> {
        // Sanitize the raw alias up front: on the bad-input path it is the only
        // request field we record, and it has not been validated yet.
        let raw_alias = safe_history_message(&input.alias);
        if let Err(error) = require_executor(caller) {
            self.record_pre_input_denial(caller, &raw_alias, "required_role", &error)
                .await;
            return Err(error);
        }
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
                    .denied("credential_not_found", "credential not found")
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
                    "wrong_credential_category",
                    "credential is not category=http",
                )
                .await;
            return Err(Error::validation("wrong_credential_category"));
        }
        if let Err(error) = validate_policy_boundary(&credential, &input) {
            recorder.denied("policy_denied", &error.to_string()).await;
            return Err(error);
        }

        let secret_ciphertext = match secret_ciphertext {
            Some(secret_ciphertext) => secret_ciphertext,
            None => {
                recorder
                    .err("secret_destroyed", "credential secret is destroyed")
                    .await;
                return Err(Error::validation("credential secret is destroyed"));
            }
        };
        let secret = self.open_http_secret(&credential.alias, &secret_ciphertext)?;
        if let Err(error) = validate_no_secret_header_override(&secret, &input) {
            recorder.denied("policy_denied", &error.to_string()).await;
            return Err(error);
        }

        let url = build_target_url(&credential.endpoint, &input)?;
        let guarded_addrs = if credential.allow_private_network {
            None
        } else {
            Some(resolve_guarded_target_addrs(&url).await?)
        };

        let started = Instant::now();
        let response = match self
            .execute_target(
                &credential,
                tls_ca.as_deref(),
                &url,
                &input,
                &secret,
                guarded_addrs.as_deref(),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                recorder
                    .err("target_request_failed", "target request failed")
                    .await;
                return Err(error);
            }
        };
        let latency_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        let status_code = i32::from(response.status.as_u16());
        let headers = filtered_response_headers(&response.headers);
        if !response_content_type_is_json(&response.headers) {
            recorder
                .err("target_not_json", "target response is not JSON")
                .await;
            return Err(Error::validation("target response is not JSON"));
        }

        let shaped = build_json_output(
            &response.body,
            opsgate_core::llm_output::JsonOutputOptions {
                max_bytes: input.max_bytes,
                max_allowed_bytes: MAX_MAX_BYTES,
                json_paths: input.jsonpath.clone(),
                transport_truncated: response.truncated,
                original_bytes: Some(response.original_bytes),
            },
        )?;
        let output = ApiCallOutput {
            status_code,
            headers,
            body: shaped.body,
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
        self.record_pre_input_denial(caller, alias, "bad_input", error)
            .await;
    }

    async fn record_pre_input_denial(
        &self,
        caller: &Caller,
        alias: &str,
        reason: &str,
        error: &Error,
    ) {
        if let Err(error) = self
            .audit
            .append(pre_input_denial_audit_params(caller, alias, reason))
            .await
        {
            tracing::error!(event = "api.call.audit_failed", detail = %error);
        }
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

    fn open_http_secret(&self, alias: &str, ciphertext: &[u8]) -> Result<Vec<SecretHeader>> {
        let plaintext = self.sealer.open(SECRET_DOMAIN, alias, ciphertext)?;
        let secret = serde_json::from_slice::<StoredSecret>(&plaintext)
            .map_err(|error| Error::internal(format!("decode credential secret: {error}")))?;
        Ok(secret
            .headers
            .into_iter()
            .map(|header| SecretHeader {
                name: header.name,
                value: SecretString::from(header.value),
            })
            .collect())
    }

    async fn execute_target(
        &self,
        credential: &Credential,
        tls_ca: Option<&[u8]>,
        url: &url::Url,
        input: &NormalizedApiCallInput,
        secret: &[SecretHeader],
        guarded_addrs: Option<&[SocketAddr]>,
    ) -> Result<TargetResponse> {
        let method = reqwest::Method::from_bytes(input.method.as_bytes())
            .map_err(|error| Error::validation(format!("invalid method: {error}")))?;
        let http = self
            .target_clients
            .client_for(credential, tls_ca, guarded_addrs, url)?;
        let mut request = http.request(method, url.clone());
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
        let mut response = request
            .send()
            .await
            .map_err(|_error| Error::internal("target request failed"))?;
        let status = response.status();
        let headers = response.headers().clone();
        let (body, original_bytes, truncated) = read_capped(&mut response, MAX_MAX_BYTES).await?;
        Ok(TargetResponse {
            status,
            headers,
            body,
            original_bytes,
            truncated,
        })
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ApiCallInput {
    pub alias: String,
    pub purpose: String,
    #[serde(default)]
    pub method: String,
    pub path: String,
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
pub struct ApiCallOutput {
    pub status_code: i32,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[schemars(schema_with = "opsgate_core::schema::json_value_schema")]
    pub body: Value,
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
    path: String,
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    body: Option<Value>,
    content_type: Option<String>,
    jsonpath: Vec<String>,
    max_bytes: usize,
}

#[derive(Debug, Deserialize)]
struct StoredSecret {
    headers: Vec<StoredSecretHeader>,
}

#[derive(Debug, Deserialize)]
struct StoredSecretHeader {
    name: String,
    value: String,
}

#[derive(Debug)]
struct TargetResponse {
    status: reqwest::StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    original_bytes: usize,
    truncated: bool,
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
    let path = validate_http_path(&input.path)?;
    let max_bytes = validate_max_bytes(
        input.max_bytes,
        DEFAULT_MAX_BYTES,
        MIN_MAX_BYTES,
        MAX_MAX_BYTES,
    )?;
    validate_json_paths(&input.jsonpath)?;
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
        path,
        query: input.query,
        headers,
        body: input.body,
        content_type,
        jsonpath,
        max_bytes,
    })
}

fn validate_policy_boundary(credential: &Credential, input: &NormalizedApiCallInput) -> Result<()> {
    if !contains_fold(&credential.policy.allowed_methods, &input.method) {
        return Err(Error::validation("method not allowed by credential policy"));
    }
    if !credential
        .policy
        .allowed_path_prefixes
        .iter()
        .any(|prefix| input.path.starts_with(prefix))
    {
        return Err(Error::validation("path not allowed by credential policy"));
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

fn build_target_url(endpoint: &str, input: &NormalizedApiCallInput) -> Result<url::Url> {
    let mut url = url::Url::parse(endpoint)
        .map_err(|error| Error::validation(format!("credential endpoint URL: {error}")))?;
    let path = join_endpoint_path(url.path(), &input.path);
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

fn join_endpoint_path(endpoint_path: &str, request_path: &str) -> String {
    let base = endpoint_path.trim_end_matches('/');
    if base.is_empty() {
        request_path.to_owned()
    } else {
        format!("{base}{request_path}")
    }
}

async fn resolve_guarded_target_addrs(url: &url::Url) -> Result<Vec<SocketAddr>> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::validation("credential endpoint requires host"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked_target_ip(ip) {
            return Err(Error::validation(
                "target IP is private/link-local/loopback",
            ));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| Error::validation(format!("resolve target host: {error}")))?;
    let addrs = addrs.collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(Error::validation("resolve target host: no IPs"));
    }
    if addrs.iter().map(|addr| addr.ip()).any(is_blocked_target_ip) {
        return Err(Error::validation(
            "target IP is private/link-local/loopback",
        ));
    }
    Ok(addrs)
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
    let mut out = Vec::new();
    let mut original = 0_usize;
    let mut truncated = false;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_error| Error::internal("read target response failed"))?
    {
        original = original.saturating_add(chunk.len());
        if out.len() < limit {
            let remaining = limit - out.len();
            let take = remaining.min(chunk.len());
            let part = chunk
                .get(..take)
                .ok_or_else(|| Error::internal("response chunk slice out of range"))?;
            out.extend_from_slice(part);
        }
        if original > limit {
            truncated = true;
        }
    }
    Ok((out, original, truncated))
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
            actor_role: Some(self.caller.role.as_str().to_owned()),
            channel: channel_str(self.caller.channel).to_owned(),
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
            path: self.input.path.clone(),
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
            truncated: output.and_then(|output| output.more.as_ref()).is_some(),
            error_kind: error_kind.map(str::to_owned),
            error_message_safe: error_message.map(safe_history_message),
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
        let channel = channel_str(self.caller.channel).to_owned();
        let params = AuditLogParams {
            action: format!("{channel}.api.call"),
            channel,
            outcome: outcome.to_owned(),
            severity: severity_for_outcome(outcome).to_owned(),
            actor_user_id: Some(self.caller.user.id),
            actor_role: Some(self.caller.role.as_str().to_owned()),
            actor_ip: self.caller.remote_ip.clone(),
            actor_user_agent: self.caller.user_agent.clone(),
            target_type: Some("credential".to_owned()),
            target_id: credential.map(|credential| credential.id.to_string()),
            target_key: Some(
                credential
                    .map(|credential| credential.alias.clone())
                    .unwrap_or_else(|| self.input.alias.clone()),
            ),
            request_id: self.caller.request_id.clone(),
            purpose: Some(self.input.purpose.clone()),
            detail: audit_detail(self.input, credential, outcome, error_kind, output),
        };
        if let Err(error) = self.audit.append(params).await {
            tracing::error!(event = "api.call.audit_failed", detail = %error);
        }
    }
}

#[derive(Debug, Clone)]
struct CredentialSnapshot {
    id: Uuid,
    owner_user_id: Uuid,
    alias: String,
    category: CredentialCategory,
    provider: String,
    env: String,
}

impl From<&Credential> for CredentialSnapshot {
    fn from(credential: &Credential) -> Self {
        Self {
            id: credential.id,
            owner_user_id: credential.owner_user_id,
            alias: credential.alias.clone(),
            category: credential.category,
            provider: credential.provider.clone(),
            env: credential.env.clone(),
        }
    }
}

fn channel_str(channel: Channel) -> &'static str {
    match channel {
        Channel::Api => "api",
        Channel::Mcp | Channel::Browser => "mcp",
    }
}

fn require_executor(caller: &Caller) -> Result<()> {
    if caller.role.can_execute() {
        Ok(())
    } else {
        Err(Error::forbidden("operator or admin role required"))
    }
}

fn severity_for_outcome(outcome: &str) -> &'static str {
    if outcome == "ok" { "info" } else { "warning" }
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
    detail.insert("path".to_owned(), serde_json::json!(input.path));
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
        detail.insert(
            "category".to_owned(),
            serde_json::json!(credential.category.as_str()),
        );
        detail.insert(
            "provider".to_owned(),
            serde_json::json!(credential.provider),
        );
        detail.insert("env".to_owned(), serde_json::json!(credential.env));
    }
    if let Some(error_kind) = error_kind {
        let key = if outcome == "denied" {
            "denial_reason"
        } else {
            "error_kind"
        };
        detail.insert(key.to_owned(), serde_json::json!(error_kind));
    }
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
        if output.more.as_ref().is_some_and(|more| more.truncated) {
            detail.insert("truncated".to_owned(), serde_json::json!(true));
        }
    }
    Value::Object(detail)
}

fn safe_history_message(value: &str) -> String {
    let replaced = value.replace(['\r', '\n'], " ");
    replaced.chars().take(512).collect()
}

/// Audit row for a pre-normalization denial. Records only the channel, the
/// (pre-sanitized) alias, and denial reason — never the raw input.
fn pre_input_denial_audit_params(caller: &Caller, alias: &str, reason: &str) -> AuditLogParams {
    let channel = channel_str(caller.channel).to_owned();
    let mut detail = serde_json::Map::new();
    detail.insert("schema_version".to_owned(), serde_json::json!(1));
    detail.insert("denial_reason".to_owned(), serde_json::json!(reason));
    AuditLogParams {
        action: format!("{channel}.api.call"),
        channel,
        outcome: "denied".to_owned(),
        severity: "warning".to_owned(),
        actor_user_id: Some(caller.user.id),
        actor_role: Some(caller.role.as_str().to_owned()),
        actor_ip: caller.remote_ip.clone(),
        actor_user_agent: caller.user_agent.clone(),
        target_type: Some("credential".to_owned()),
        target_id: None,
        target_key: Some(alias.to_owned()),
        request_id: caller.request_id.clone(),
        purpose: None,
        detail: Value::Object(detail),
    }
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
        actor_role: Some(caller.role.as_str().to_owned()),
        channel: channel_str(caller.channel).to_owned(),
        request_id: caller.request_id.clone(),
        credential_id: None,
        credential_alias: alias.to_owned(),
        credential_category: String::new(),
        credential_provider: String::new(),
        credential_env: String::new(),
        method: String::new(),
        path: String::new(),
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
        error_message_safe: Some(safe_history_message(&error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use opsgate_domain::credential::CredentialPolicy;
    use secrecy::SecretString;

    fn base_input() -> ApiCallInput {
        ApiCallInput {
            alias: "prod".to_owned(),
            purpose: "Check pod phases".to_owned(),
            method: "GET".to_owned(),
            path: "/api/v1/pods".to_owned(),
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
            endpoint: "https://api.example.test".to_owned(),
            description: String::new(),
            env: "prod".to_owned(),
            tags: Vec::new(),
            policy,
            allow_private_network: false,
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
        input.path = "/api/../secret".to_owned();
        assert!(normalize_input(input.clone()).is_err());
        input.path = "/api/v1/pods".to_owned();
        input.jsonpath = vec!["$..metadata.name".to_owned()];
        assert!(normalize_input(input.clone()).is_err());
        input.jsonpath = Vec::new();
        input
            .headers
            .insert("Accept".to_owned(), "text/plain".to_owned());
        assert!(normalize_input(input).is_err());
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
            allowed_path_prefixes: vec!["/api/".to_owned()],
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
            path: "/other".to_owned(),
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
    fn target_url_preserves_endpoint_base_path() -> Result<()> {
        let input = normalize_input(ApiCallInput {
            path: "/v1/pods".to_owned(),
            query: BTreeMap::from([("label".to_owned(), "app=web".to_owned())]),
            ..base_input()
        })?;
        let url = build_target_url("https://api.example.test/base/", &input)?;
        assert_eq!(
            url.as_str(),
            "https://api.example.test/base/v1/pods?label=app%3Dweb"
        );

        let url = build_target_url("https://api.example.test", &input)?;
        assert_eq!(
            url.as_str(),
            "https://api.example.test/v1/pods?label=app%3Dweb"
        );
        Ok(())
    }

    #[test]
    fn history_message_is_bounded_and_single_line() {
        let message = format!("secret\r\n{}", "x".repeat(600));
        let safe = safe_history_message(&message);
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
            Some("policy_denied"),
            None,
        );
        let serialized = detail.to_string();
        assert!(serialized.contains("query_keys"));
        assert!(serialized.contains("request_header_keys"));
        assert!(serialized.contains("denial_reason"));
        assert!(!serialized.contains("query-secret"));
        assert!(!serialized.contains("body-secret"));
        assert!(!serialized.contains("endpoint"));
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("\"reason\""));
        Ok(())
    }

    #[tokio::test]
    async fn guarded_target_resolution_blocks_private_literal() -> Result<()> {
        let private = url::Url::parse("https://127.0.0.1")
            .map_err(|error| Error::internal(format!("parse URL: {error}")))?;
        assert!(resolve_guarded_target_addrs(&private).await.is_err());

        let public = url::Url::parse("https://93.184.216.34")
            .map_err(|error| Error::internal(format!("parse URL: {error}")))?;
        let addrs = resolve_guarded_target_addrs(&public).await?;
        assert_eq!(addrs, [SocketAddr::from(([93, 184, 216, 34], 443))]);
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
                role: opsgate_domain::Role::Operator,
                is_active: true,
                created_at: now,
                updated_at: now,
            },
            channel: opsgate_domain::Channel::Mcp,
            role: opsgate_domain::Role::Operator,
            request_id: None,
            remote_ip: None,
            user_agent: None,
        }
    }

    #[test]
    fn bad_input_denial_is_recorded_safely() {
        let caller = test_caller();
        let error = Error::validation("purpose must be at least 8 characters");

        let history = pre_input_denial_history_params(&caller, "prod", "bad_input", &error);
        assert_eq!(history.outcome, "denied");
        assert_eq!(history.error_kind.as_deref(), Some("bad_input"));
        assert!(history.purpose.is_none());
        assert_eq!(history.credential_alias, "prod");
        assert!(history.method.is_empty());
        assert_eq!(history.status_code, None);

        let audit = pre_input_denial_audit_params(&caller, "prod", "bad_input");
        assert_eq!(audit.outcome, "denied");
        assert_eq!(audit.action, "mcp.api.call");
        assert!(audit.purpose.is_none());
        assert_eq!(
            audit.detail.get("denial_reason"),
            Some(&serde_json::json!("bad_input"))
        );
    }

    #[test]
    fn required_role_denial_is_recorded_safely() {
        let caller = test_caller();
        let error = Error::forbidden("operator or admin role required");

        let history = pre_input_denial_history_params(&caller, "prod", "required_role", &error);
        assert_eq!(history.outcome, "denied");
        assert_eq!(history.error_kind.as_deref(), Some("required_role"));
        assert!(history.purpose.is_none());
        assert_eq!(history.credential_alias, "prod");
        assert!(history.method.is_empty());

        let audit = pre_input_denial_audit_params(&caller, "prod", "required_role");
        assert_eq!(audit.outcome, "denied");
        assert_eq!(
            audit.detail.get("denial_reason"),
            Some(&serde_json::json!("required_role"))
        );
    }

    #[test]
    fn api_call_requires_operator_or_admin_role() {
        let mut caller = test_caller();
        caller.role = opsgate_domain::Role::Viewer;
        assert!(matches!(
            require_executor(&caller),
            Err(Error::Forbidden(_))
        ));
        caller.role = opsgate_domain::Role::Operator;
        assert!(require_executor(&caller).is_ok());
        caller.role = opsgate_domain::Role::Admin;
        assert!(require_executor(&caller).is_ok());
    }
}

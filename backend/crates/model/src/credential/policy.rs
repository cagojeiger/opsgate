use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use opsgate_core::{Error, Result};

use super::header::{canonical_header_name, header_blocked, valid_header_name};
use super::model::CredentialCategory;

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CredentialPolicy {
    /// HTTP methods allowed for api_call. Empty means GET only after normalization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_methods: Vec<String>,
    /// api_call.request_path prefixes allowed for this HTTP credential. Empty means / after normalization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_request_path_prefixes: Vec<String>,
    /// Query string keys that api_call must not send.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_query_keys: Vec<String>,
    /// Extra request headers api_call may send. Secret/unsafe headers stay blocked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_request_headers: Vec<String>,
    /// Allow sql_schema to expose schema metadata for this SQL credential.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_metadata: bool,
    /// Allow sql_query EXPLAIN without ANALYZE.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_explain: bool,
    /// Allow sql_query EXPLAIN ANALYZE. This can execute the query, so enable carefully.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_explain_analyze: bool,
    /// SQL function names blocked even in read-only SELECT/WITH queries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_functions: Vec<String>,
    /// Maximum SQL rows or schema rows allowed. Zero means service default.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_rows: u32,
    /// Maximum response bytes allowed. Zero means service default.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_bytes: u32,
    /// Maximum target timeout in milliseconds. Zero means service default.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub timeout_ms: u32,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

pub fn normalize_policy_for_category(
    mut policy: CredentialPolicy,
    category: CredentialCategory,
) -> CredentialPolicy {
    match category {
        CredentialCategory::Http => normalize_http_policy(&mut policy),
        CredentialCategory::Sql => normalize_sql_policy(&mut policy),
    }
    policy
}

pub fn validate_policy_for_category(
    policy: &CredentialPolicy,
    category: CredentialCategory,
) -> Result<()> {
    match category {
        CredentialCategory::Http => validate_http_policy(policy),
        CredentialCategory::Sql => validate_sql_policy(policy),
    }
}

fn normalize_http_policy(policy: &mut CredentialPolicy) {
    if policy.allowed_methods.is_empty() {
        policy.allowed_methods.push("GET".to_owned());
    }
    if policy.allowed_request_path_prefixes.is_empty() {
        policy.allowed_request_path_prefixes.push("/".to_owned());
    }
    for method in &mut policy.allowed_methods {
        *method = method.trim().to_ascii_uppercase();
    }
    for header in &mut policy.allowed_request_headers {
        *header = canonical_header_name(header);
    }
}

fn normalize_sql_policy(policy: &mut CredentialPolicy) {
    for function in &mut policy.denied_functions {
        *function = function.trim().to_ascii_lowercase();
    }
}

fn validate_http_policy(policy: &CredentialPolicy) -> Result<()> {
    reject_sql_only_policy_fields(policy)?;
    for method in &policy.allowed_methods {
        if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
            return Err(Error::validation(format!(
                "unsupported method in allowed_methods: {method:?}"
            )));
        }
    }
    for prefix in &policy.allowed_request_path_prefixes {
        if !valid_request_path_prefix(prefix) {
            return Err(Error::validation(format!(
                "allowed_request_path_prefix {prefix:?} must be an absolute request path prefix"
            )));
        }
    }
    for key in &policy.denied_query_keys {
        if key.is_empty() {
            return Err(Error::validation(
                "denied_query_keys must not contain empty keys",
            ));
        }
    }
    for header in &policy.allowed_request_headers {
        if !valid_header_name(header) {
            return Err(Error::validation(format!(
                "invalid allowed_request_headers entry: {header:?}"
            )));
        }
        if header_blocked(header) {
            return Err(Error::validation(format!(
                "allowed_request_headers must not include blocked header {header:?}"
            )));
        }
    }
    Ok(())
}

pub fn request_path_matches_prefix(request_path: &str, prefix: &str) -> bool {
    prefix == "/"
        || request_path == prefix
        || request_path
            .strip_prefix(prefix.trim_end_matches('/'))
            .is_some_and(|tail| tail.starts_with('/'))
}

fn valid_request_path_prefix(prefix: &str) -> bool {
    prefix.starts_with('/')
        && !prefix.contains(['\0', '\r', '\n', '?', '#'])
        && !prefix.contains("..")
        && !prefix.contains("//")
}

fn reject_sql_only_policy_fields(policy: &CredentialPolicy) -> Result<()> {
    if policy.allow_metadata {
        return Err(Error::validation(
            "policy.allow_metadata is only supported for sql credentials",
        ));
    }
    if policy.allow_explain {
        return Err(Error::validation(
            "policy.allow_explain is only supported for sql credentials",
        ));
    }
    if policy.allow_explain_analyze {
        return Err(Error::validation(
            "policy.allow_explain_analyze is only supported for sql credentials",
        ));
    }
    if !policy.denied_functions.is_empty() {
        return Err(Error::validation(
            "policy.denied_functions is only supported for sql credentials",
        ));
    }
    if policy.max_rows > 0 {
        return Err(Error::validation(
            "policy.max_rows is only supported for sql credentials",
        ));
    }
    if policy.max_bytes > 0 {
        return Err(Error::validation(
            "policy.max_bytes is only supported for sql credentials",
        ));
    }
    if policy.timeout_ms > 0 {
        return Err(Error::validation(
            "policy.timeout_ms is only supported for sql credentials",
        ));
    }
    Ok(())
}

fn reject_http_only_policy_fields(policy: &CredentialPolicy) -> Result<()> {
    if !policy.allowed_methods.is_empty() {
        return Err(Error::validation(
            "policy.allowed_methods is only supported for http credentials",
        ));
    }
    if !policy.allowed_request_path_prefixes.is_empty() {
        return Err(Error::validation(
            "policy.allowed_request_path_prefixes is only supported for http credentials",
        ));
    }
    if !policy.denied_query_keys.is_empty() {
        return Err(Error::validation(
            "policy.denied_query_keys is only supported for http credentials",
        ));
    }
    if !policy.allowed_request_headers.is_empty() {
        return Err(Error::validation(
            "policy.allowed_request_headers is only supported for http credentials",
        ));
    }
    Ok(())
}

fn validate_sql_policy(policy: &CredentialPolicy) -> Result<()> {
    reject_http_only_policy_fields(policy)?;
    if policy.allow_explain_analyze && !policy.allow_explain {
        return Err(Error::validation(
            "sql policy allow_explain_analyze requires allow_explain=true",
        ));
    }
    for function in &policy.denied_functions {
        if function.trim().is_empty() || function.contains(['\0', '\r', '\n']) {
            return Err(Error::validation(format!(
                "invalid denied function {function:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_policy_defaults_to_get_root() {
        let policy =
            normalize_policy_for_category(CredentialPolicy::default(), CredentialCategory::Http);
        assert_eq!(policy.allowed_methods, ["GET"]);
        assert_eq!(policy.allowed_request_path_prefixes, ["/"]);
        assert!(validate_policy_for_category(&policy, CredentialCategory::Http).is_ok());
    }

    #[test]
    fn http_policy_rejects_bad_method_and_blocked_header() {
        let policy = normalize_policy_for_category(
            CredentialPolicy {
                allowed_methods: vec!["trace".to_owned()],
                ..CredentialPolicy::default()
            },
            CredentialCategory::Http,
        );
        assert!(validate_policy_for_category(&policy, CredentialCategory::Http).is_err());

        let policy = normalize_policy_for_category(
            CredentialPolicy {
                allowed_request_headers: vec!["authorization".to_owned()],
                ..CredentialPolicy::default()
            },
            CredentialCategory::Http,
        );
        assert!(validate_policy_for_category(&policy, CredentialCategory::Http).is_err());
    }

    #[test]
    fn sql_policy_rejects_explain_analyze_without_explain() {
        let policy = normalize_policy_for_category(
            CredentialPolicy {
                allow_explain_analyze: true,
                ..CredentialPolicy::default()
            },
            CredentialCategory::Sql,
        );
        assert!(validate_policy_for_category(&policy, CredentialCategory::Sql).is_err());
    }

    #[test]
    fn http_policy_rejects_sql_only_fields() {
        for (policy, expected) in [
            (
                CredentialPolicy {
                    allow_metadata: true,
                    ..CredentialPolicy::default()
                },
                "allow_metadata",
            ),
            (
                CredentialPolicy {
                    allow_explain: true,
                    ..CredentialPolicy::default()
                },
                "allow_explain",
            ),
            (
                CredentialPolicy {
                    allow_explain_analyze: true,
                    ..CredentialPolicy::default()
                },
                "allow_explain_analyze",
            ),
            (
                CredentialPolicy {
                    denied_functions: vec!["version".to_owned()],
                    ..CredentialPolicy::default()
                },
                "denied_functions",
            ),
            (
                CredentialPolicy {
                    max_rows: 100,
                    ..CredentialPolicy::default()
                },
                "max_rows",
            ),
            (
                CredentialPolicy {
                    max_bytes: 4096,
                    ..CredentialPolicy::default()
                },
                "max_bytes",
            ),
            (
                CredentialPolicy {
                    timeout_ms: 3000,
                    ..CredentialPolicy::default()
                },
                "timeout_ms",
            ),
        ] {
            let policy = normalize_policy_for_category(policy, CredentialCategory::Http);
            let err = validate_policy_for_category(&policy, CredentialCategory::Http)
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default();
            assert!(err.contains(expected), "{err:?} should mention {expected}");
        }
    }

    #[test]
    fn sql_policy_rejects_http_only_fields() {
        for (policy, expected) in [
            (
                CredentialPolicy {
                    allowed_methods: vec!["GET".to_owned()],
                    ..CredentialPolicy::default()
                },
                "allowed_methods",
            ),
            (
                CredentialPolicy {
                    allowed_request_path_prefixes: vec!["/api".to_owned()],
                    ..CredentialPolicy::default()
                },
                "allowed_request_path_prefixes",
            ),
            (
                CredentialPolicy {
                    denied_query_keys: vec!["token".to_owned()],
                    ..CredentialPolicy::default()
                },
                "denied_query_keys",
            ),
            (
                CredentialPolicy {
                    allowed_request_headers: vec!["X-Test".to_owned()],
                    ..CredentialPolicy::default()
                },
                "allowed_request_headers",
            ),
        ] {
            let policy = normalize_policy_for_category(policy, CredentialCategory::Sql);
            let err = validate_policy_for_category(&policy, CredentialCategory::Sql)
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default();
            assert!(err.contains(expected), "{err:?} should mention {expected}");
        }
    }

    #[test]
    fn request_path_prefix_matching_is_segment_aware() {
        assert!(request_path_matches_prefix("/api/v1", "/api"));
        assert!(request_path_matches_prefix("/api", "/api"));
        assert!(!request_path_matches_prefix("/apis", "/api"));
    }
}

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use opsgate_core::{Error, Result};

use super::header::{canonical_header_name, header_blocked, valid_header_name};
use super::model::CredentialCategory;

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CredentialPolicy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_query_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_request_headers: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_metadata: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_explain: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_explain_analyze: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_functions: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_rows: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_bytes: u32,
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
    if policy.allowed_path_prefixes.is_empty() {
        policy.allowed_path_prefixes.push("/".to_owned());
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
    for method in &policy.allowed_methods {
        if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
            return Err(Error::validation(format!(
                "unsupported method in allowed_methods: {method:?}"
            )));
        }
    }
    for prefix in &policy.allowed_path_prefixes {
        if !prefix.starts_with('/') {
            return Err(Error::validation(format!(
                "allowed_path_prefix {prefix:?} must start with /"
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

fn validate_sql_policy(policy: &CredentialPolicy) -> Result<()> {
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
        assert_eq!(policy.allowed_path_prefixes, ["/"]);
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
}

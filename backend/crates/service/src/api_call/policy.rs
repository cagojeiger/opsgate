use opsgate_core::Error;
use opsgate_model::credential::{
    Credential, SecretHeader, contains_fold, header_blocked, request_path_matches_prefix,
};
use serde_json::{Value, json};

use super::input::NormalizedApiCallInput;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ApiPolicyDenial {
    MethodNotAllowed {
        allowed_methods: Vec<String>,
    },
    RequestPathNotAllowed {
        allowed_request_path_prefixes: Vec<String>,
    },
    QueryKeyDenied {
        denied_query_keys: Vec<String>,
    },
    RequestHeaderBlocked,
    RequestHeaderNotAllowed {
        allowed_request_headers: Vec<String>,
    },
    SecretHeaderOverride,
}

impl ApiPolicyDenial {
    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::MethodNotAllowed { .. } => "policy_method_not_allowed",
            Self::RequestPathNotAllowed { .. } => "policy_request_path_not_allowed",
            Self::QueryKeyDenied { .. } => "policy_query_key_denied",
            Self::RequestHeaderBlocked => "policy_request_header_blocked",
            Self::RequestHeaderNotAllowed { .. } => "policy_request_header_not_allowed",
            Self::SecretHeaderOverride => "policy_secret_header_override",
        }
    }

    pub(super) fn message(&self) -> &'static str {
        match self {
            Self::MethodNotAllowed { .. } => "method not allowed by credential policy",
            Self::RequestPathNotAllowed { .. } => "request_path not allowed by credential policy",
            Self::QueryKeyDenied { .. } => "query key denied by credential policy",
            Self::RequestHeaderBlocked => "blocked request header",
            Self::RequestHeaderNotAllowed { .. } => {
                "request header not allowed by credential policy"
            }
            Self::SecretHeaderOverride => "caller header cannot override sealed secret header",
        }
    }

    fn hint(&self) -> &'static str {
        match self {
            Self::MethodNotAllowed { .. } => "Use one of the credential policy allowed_methods.",
            Self::RequestPathNotAllowed { .. } => {
                "Use a request_path under one of the credential policy allowed_request_path_prefixes."
            }
            Self::QueryKeyDenied { .. } => "Remove query keys denied by credential policy.",
            Self::RequestHeaderBlocked => {
                "Remove blocked transport or auth headers from the request."
            }
            Self::RequestHeaderNotAllowed { .. } => {
                "Use only request headers listed in credential policy allowed_request_headers."
            }
            Self::SecretHeaderOverride => {
                "Remove caller-supplied headers that are sealed on the credential."
            }
        }
    }

    fn data(&self) -> Value {
        match self {
            Self::MethodNotAllowed { allowed_methods } => policy_denial_data(
                "use_allowed_method",
                Some(json!({ "allowed_methods": allowed_methods })),
            ),
            Self::RequestPathNotAllowed {
                allowed_request_path_prefixes,
            } => policy_denial_data(
                "use_allowed_request_path_prefix",
                Some(json!({ "allowed_request_path_prefixes": allowed_request_path_prefixes })),
            ),
            Self::QueryKeyDenied { denied_query_keys } => policy_denial_data(
                "remove_denied_query_key",
                Some(json!({ "denied_query_keys": denied_query_keys })),
            ),
            Self::RequestHeaderBlocked => policy_denial_data("remove_blocked_request_header", None),
            Self::RequestHeaderNotAllowed {
                allowed_request_headers,
            } => policy_denial_data(
                "use_allowed_request_header",
                Some(json!({ "allowed_request_headers": allowed_request_headers })),
            ),
            Self::SecretHeaderOverride => policy_denial_data("remove_secret_header_override", None),
        }
    }

    pub(super) fn into_error(self) -> Error {
        Error::user_safe_with_data(self.kind(), self.message(), Some(self.hint()), self.data())
    }
}

fn policy_denial_data(next_action: &'static str, policy_hint: Option<Value>) -> Value {
    let mut data = serde_json::Map::new();
    data.insert("next_action".to_owned(), json!(next_action));
    if let Some(policy_hint) = policy_hint {
        data.insert("policy_hint".to_owned(), policy_hint);
    }
    Value::Object(data)
}

pub(super) fn validate_policy_boundary(
    credential: &Credential,
    input: &NormalizedApiCallInput,
) -> std::result::Result<(), ApiPolicyDenial> {
    if !contains_fold(&credential.policy.allowed_methods, &input.method) {
        return Err(ApiPolicyDenial::MethodNotAllowed {
            allowed_methods: credential.policy.allowed_methods.clone(),
        });
    }
    if !credential
        .policy
        .allowed_request_path_prefixes
        .iter()
        .any(|prefix| request_path_matches_prefix(&input.request_path, prefix))
    {
        return Err(ApiPolicyDenial::RequestPathNotAllowed {
            allowed_request_path_prefixes: credential.policy.allowed_request_path_prefixes.clone(),
        });
    }
    for key in input.query.keys() {
        if contains_fold(&credential.policy.denied_query_keys, key) {
            return Err(ApiPolicyDenial::QueryKeyDenied {
                denied_query_keys: credential.policy.denied_query_keys.clone(),
            });
        }
    }
    for name in input.headers.keys() {
        if header_blocked(name) {
            return Err(ApiPolicyDenial::RequestHeaderBlocked);
        }
        if !contains_fold(&credential.policy.allowed_request_headers, name) {
            return Err(ApiPolicyDenial::RequestHeaderNotAllowed {
                allowed_request_headers: credential.policy.allowed_request_headers.clone(),
            });
        }
    }
    Ok(())
}

pub(super) fn validate_no_secret_header_override(
    secret: &[SecretHeader],
    input: &NormalizedApiCallInput,
) -> std::result::Result<(), ApiPolicyDenial> {
    for header in secret {
        if input
            .headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case(&header.name))
        {
            return Err(ApiPolicyDenial::SecretHeaderOverride);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use opsgate_model::credential::{
        CredentialCategory, CredentialPolicy, CredentialTarget, SecretHeader,
    };
    use secrecy::SecretString;
    use uuid::Uuid;

    use super::super::input::{ApiCallInput, normalize_input};
    use super::*;

    fn expect_denial(
        result: std::result::Result<(), ApiPolicyDenial>,
    ) -> opsgate_core::Result<ApiPolicyDenial> {
        result
            .err()
            .ok_or_else(|| Error::internal("expected policy denial"))
    }

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
    fn policy_boundary_rejects_docs_denials() -> opsgate_core::Result<()> {
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
        assert_eq!(
            expect_denial(validate_policy_boundary(&credential, &denied_query))?.kind(),
            "policy_query_key_denied"
        );

        let disallowed_header = normalize_input(ApiCallInput {
            headers: BTreeMap::from([("X-Trace-Id".to_owned(), "abc".to_owned())]),
            ..base_input()
        })?;
        assert_eq!(
            expect_denial(validate_policy_boundary(&credential, &disallowed_header))?.kind(),
            "policy_request_header_not_allowed"
        );

        let blocked_header = normalize_input(ApiCallInput {
            headers: BTreeMap::from([("Host".to_owned(), "example.test".to_owned())]),
            ..base_input()
        })?;
        assert_eq!(
            expect_denial(validate_policy_boundary(&credential, &blocked_header))?.kind(),
            "policy_request_header_blocked"
        );

        let method_denied = normalize_input(ApiCallInput {
            method: "DELETE".to_owned(),
            ..base_input()
        })?;
        assert_eq!(
            expect_denial(validate_policy_boundary(&credential, &method_denied))?.kind(),
            "policy_method_not_allowed"
        );

        let path_denied = normalize_input(ApiCallInput {
            request_path: "/other".to_owned(),
            ..base_input()
        })?;
        assert_eq!(
            expect_denial(validate_policy_boundary(&credential, &path_denied))?.kind(),
            "policy_request_path_not_allowed"
        );
        Ok(())
    }

    #[test]
    fn policy_denial_error_includes_public_recovery_data() -> opsgate_core::Result<()> {
        let credential = http_credential(CredentialPolicy {
            allowed_methods: vec!["GET".to_owned()],
            ..CredentialPolicy::default()
        });
        let method_denied = normalize_input(ApiCallInput {
            method: "DELETE".to_owned(),
            ..base_input()
        })?;

        let error =
            expect_denial(validate_policy_boundary(&credential, &method_denied))?.into_error();
        let Error::UserSafe {
            kind, data, hint, ..
        } = error
        else {
            return Err(Error::internal("expected user-safe policy denial"));
        };

        assert_eq!(kind, "policy_method_not_allowed");
        assert!(
            hint.as_deref()
                .is_some_and(|hint| hint.contains("allowed_methods"))
        );
        let data = data.ok_or_else(|| Error::internal("policy denial data missing"))?;
        assert_eq!(
            data.get("next_action").and_then(Value::as_str),
            Some("use_allowed_method")
        );
        assert_eq!(
            data.pointer("/policy_hint/allowed_methods/0")
                .and_then(Value::as_str),
            Some("GET")
        );
        Ok(())
    }

    #[test]
    fn policy_boundary_rejects_secret_header_override() -> opsgate_core::Result<()> {
        let input = normalize_input(ApiCallInput {
            headers: BTreeMap::from([("X-Api-Key".to_owned(), "caller-value".to_owned())]),
            ..base_input()
        })?;
        let secret = vec![SecretHeader {
            name: "x-api-key".to_owned(),
            value: SecretString::from("sealed-value"),
        }];
        assert_eq!(
            expect_denial(validate_no_secret_header_override(&secret, &input))?.kind(),
            "policy_secret_header_override"
        );
        Ok(())
    }
}

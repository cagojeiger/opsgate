use opsgate_core::Error;
use opsgate_model::credential::{
    Credential, contains_fold, header_blocked, request_path_matches_prefix,
};

use super::input::NormalizedApiCallInput;

#[derive(Debug)]
pub(super) enum ApiPolicyDenial {
    MethodNotAllowed,
    RequestPathNotAllowed,
    QueryKeyDenied,
    RequestHeaderBlocked,
    RequestHeaderNotAllowed,
}

impl ApiPolicyDenial {
    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::MethodNotAllowed => "policy_method_not_allowed",
            Self::RequestPathNotAllowed => "policy_request_path_not_allowed",
            Self::QueryKeyDenied => "policy_query_key_denied",
            Self::RequestHeaderBlocked => "policy_request_header_blocked",
            Self::RequestHeaderNotAllowed => "policy_request_header_not_allowed",
        }
    }

    pub(super) fn message(&self) -> &'static str {
        match self {
            Self::MethodNotAllowed => "method not allowed by credential policy",
            Self::RequestPathNotAllowed => "request_path not allowed by credential policy",
            Self::QueryKeyDenied => "query key denied by credential policy",
            Self::RequestHeaderBlocked => "blocked request header",
            Self::RequestHeaderNotAllowed => "request header not allowed by credential policy",
        }
    }

    fn hint(&self) -> &'static str {
        match self {
            Self::MethodNotAllowed => {
                "Use credential_list to inspect allowed_methods for this alias, then retry with an allowed method."
            }
            Self::RequestPathNotAllowed => {
                "Use credential_list to inspect allowed_request_path_prefixes for this alias, then retry under an allowed prefix."
            }
            Self::QueryKeyDenied => {
                "Use credential_list to inspect denied_query_keys for this alias, then remove denied query keys."
            }
            Self::RequestHeaderBlocked => {
                "Remove blocked transport or auth headers from the request."
            }
            Self::RequestHeaderNotAllowed => {
                "Use credential_list to inspect allowed_request_headers for this alias, then retry with only allowed headers."
            }
        }
    }

    pub(super) fn into_error(self) -> Error {
        Error::user_safe(self.kind(), self.message(), Some(self.hint()))
    }
}

pub(super) fn validate_policy_boundary(
    credential: &Credential,
    input: &NormalizedApiCallInput,
) -> std::result::Result<(), ApiPolicyDenial> {
    if !contains_fold(&credential.policy.allowed_methods, &input.method) {
        return Err(ApiPolicyDenial::MethodNotAllowed);
    }
    if !credential
        .policy
        .allowed_request_path_prefixes
        .iter()
        .any(|prefix| request_path_matches_prefix(&input.request_path, prefix))
    {
        return Err(ApiPolicyDenial::RequestPathNotAllowed);
    }
    for key in input.query.keys() {
        if contains_fold(&credential.policy.denied_query_keys, key) {
            return Err(ApiPolicyDenial::QueryKeyDenied);
        }
    }
    for name in input.headers.keys() {
        if header_blocked(name) {
            return Err(ApiPolicyDenial::RequestHeaderBlocked);
        }
        if !contains_fold(&credential.policy.allowed_request_headers, name) {
            return Err(ApiPolicyDenial::RequestHeaderNotAllowed);
        }
    }
    Ok(())
}

pub(super) fn caller_overrides_secret_header<'a, I>(
    secret_header_names: I,
    input: &NormalizedApiCallInput,
) -> bool
where
    I: IntoIterator<Item = &'a str>,
{
    for secret_header_name in secret_header_names {
        if input
            .headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case(secret_header_name))
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use opsgate_model::credential::{CredentialCategory, CredentialPolicy, CredentialTarget};
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
            table: None,
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
    fn policy_denial_error_includes_public_recovery_hint() -> opsgate_core::Result<()> {
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
        let Error::UserSafe { kind, hint, .. } = error else {
            return Err(Error::internal("expected user-safe policy denial"));
        };

        assert_eq!(kind, "policy_method_not_allowed");
        assert!(hint.as_deref().is_some_and(
            |hint| hint.contains("credential_list") && hint.contains("allowed_methods")
        ));
        Ok(())
    }

    #[test]
    fn detects_secret_header_override_defensively() -> opsgate_core::Result<()> {
        let input = normalize_input(ApiCallInput {
            headers: BTreeMap::from([("X-Api-Key".to_owned(), "caller-value".to_owned())]),
            ..base_input()
        })?;
        assert!(caller_overrides_secret_header(["x-api-key"], &input));
        Ok(())
    }
}

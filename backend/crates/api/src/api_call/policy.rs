use opsgate_core::{Error, Result};
use opsgate_model::credential::{
    Credential, SecretHeader, contains_fold, header_blocked, request_path_matches_prefix,
};

use super::input::NormalizedApiCallInput;

pub(super) fn validate_policy_boundary(
    credential: &Credential,
    input: &NormalizedApiCallInput,
) -> Result<()> {
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

pub(super) fn validate_no_secret_header_override(
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
}

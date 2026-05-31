use std::collections::BTreeMap;

use opsgate_core::{Error, Result};
use opsgate_db::CredentialSummaryRows;
use opsgate_model::credential::{
    Credential, validate_alias as validate_credential_alias,
    validate_env as validate_credential_env, validate_provider as validate_credential_provider,
    validate_tag as validate_credential_tag,
};

use super::input::ListCredentialsInput;

const MAX_LIST_Q: usize = 128;
const MAX_LIST_FIELDS: usize = 8;

#[derive(Debug, Clone)]
pub struct CredentialListPage {
    pub credentials: Vec<Credential>,
    pub limit: i64,
    pub has_more: bool,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct CredentialSummary {
    pub total: i64,
    pub by_category: BTreeMap<String, i64>,
    pub by_provider: BTreeMap<String, i64>,
    pub tags: BTreeMap<String, i64>,
}

impl From<CredentialSummaryRows> for CredentialSummary {
    fn from(rows: CredentialSummaryRows) -> Self {
        Self {
            total: rows.total,
            by_category: count_map(rows.by_category),
            by_provider: count_map(rows.by_provider),
            tags: count_map(rows.tags),
        }
    }
}

pub(super) fn normalize_list_input(mut input: ListCredentialsInput) -> ListCredentialsInput {
    input.provider = trim_filter_optional(input.provider);
    input.env = trim_filter_optional(input.env);
    input.tag = trim_filter_optional(input.tag).map(|tag| tag.to_ascii_lowercase());
    input.q = trim_filter_optional(input.q);
    input.cursor = trim_filter_optional(input.cursor);
    input.fields = input.fields.map(normalize_list_fields);
    input
}

pub(super) fn validate_list_input(input: &ListCredentialsInput, max_limit: i64) -> Result<()> {
    if let Some(provider) = &input.provider {
        validate_credential_provider(provider)?;
    }
    if let Some(env) = &input.env {
        validate_credential_env(env)?;
    }
    if let Some(tag) = &input.tag {
        validate_credential_tag(tag)?;
    }
    if let Some(q) = &input.q
        && (q.len() > MAX_LIST_Q || q.contains(['\r', '\n']))
    {
        return Err(Error::validation(format!(
            "q must be at most {MAX_LIST_Q} characters without CR/LF"
        )));
    }
    if let Some(fields) = &input.fields {
        if fields.len() > MAX_LIST_FIELDS {
            return Err(Error::validation(format!(
                "fields count must be <= {MAX_LIST_FIELDS}"
            )));
        }
        for field in fields {
            if !allowed_list_field(field) {
                return Err(Error::validation(format!("unsupported field {field:?}")));
            }
        }
    }
    if let Some(limit) = input.limit
        && !(1..=max_limit).contains(&limit)
    {
        return Err(Error::validation(format!(
            "limit must be in range [1,{max_limit}]"
        )));
    }
    if let Some(cursor) = &input.cursor {
        validate_credential_alias(cursor)?;
    }
    Ok(())
}

fn count_map(rows: Vec<opsgate_db::credential_repo::CountRow>) -> BTreeMap<String, i64> {
    rows.into_iter().map(|row| (row.key, row.count)).collect()
}

fn normalize_list_fields(fields: Vec<String>) -> Vec<String> {
    if fields.is_empty() {
        return fields;
    }
    let mut out = vec!["alias".to_owned()];
    for field in fields {
        let field = field.trim().to_owned();
        if !field.is_empty() && !out.iter().any(|existing| existing == &field) {
            out.push(field);
        }
    }
    out
}

fn allowed_list_field(field: &str) -> bool {
    matches!(
        field,
        "alias"
            | "category"
            | "provider"
            | "env"
            | "tags"
            | "description"
            | "policy"
            | "allow_private_network"
            | "allow_insecure_transport"
    )
}

fn trim_optional(value: Option<String>) -> Option<String> {
    value.map(|value| value.trim().to_owned())
}

fn trim_filter_optional(value: Option<String>) -> Option<String> {
    trim_optional(value).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use opsgate_model::credential::CredentialCategory;

    use super::*;

    #[test]
    fn list_input_validation_matches_go_boundaries() {
        let valid = normalize_list_input(ListCredentialsInput {
            category: Some(CredentialCategory::Http),
            provider: Some(" k8s ".to_owned()),
            env: Some("prod".to_owned()),
            tag: Some(" Cluster ".to_owned()),
            q: Some(" osaka ".to_owned()),
            fields: Some(vec![" provider ".to_owned(), "env".to_owned()]),
            limit: Some(50),
            cursor: Some("prod-api".to_owned()),
        });
        assert!(validate_list_input(&valid, 100).is_ok());
        assert_eq!(valid.tag.as_deref(), Some("cluster"));

        for input in [
            ListCredentialsInput {
                provider: Some("Bad".to_owned()),
                ..valid.clone()
            },
            ListCredentialsInput {
                env: Some("qa".to_owned()),
                ..valid.clone()
            },
            ListCredentialsInput {
                tag: Some("bad space".to_owned()),
                ..valid.clone()
            },
            ListCredentialsInput {
                q: Some("bad\nquery".to_owned()),
                ..valid.clone()
            },
            ListCredentialsInput {
                fields: Some((0..9).map(|idx| format!("field{idx}")).collect()),
                ..valid.clone()
            },
            ListCredentialsInput {
                fields: Some(vec!["origin".to_owned()]),
                ..valid.clone()
            },
            ListCredentialsInput {
                limit: Some(101),
                ..valid.clone()
            },
            ListCredentialsInput {
                cursor: Some("bad cursor".to_owned()),
                ..valid
            },
        ] {
            assert!(validate_list_input(&normalize_list_input(input), 100).is_err());
        }
    }
}

use opsgate_core::{Error, Result};
use opsgate_model::credential::CredentialPolicy;

use super::input::{MODE_TABLES, NormalizedInput};

pub(super) fn validate_policy(policy: &CredentialPolicy, input: &NormalizedInput) -> Result<()> {
    if policy.allow_explain_analyze && !policy.allow_explain {
        return Err(Error::validation("sql policy is invalid"));
    }
    if policy.max_rows > 0
        && input.mode == MODE_TABLES
        && input.limit > i32::try_from(policy.max_rows).unwrap_or(i32::MAX)
    {
        return Err(Error::validation("limit exceeds credential policy"));
    }
    if policy.max_bytes > 0
        && input.max_bytes > usize::try_from(policy.max_bytes).unwrap_or(usize::MAX)
    {
        return Err(Error::validation("max_bytes exceeds credential policy"));
    }
    if policy.timeout_ms > 0 && input.timeout_ms > policy.timeout_ms {
        return Err(Error::validation("timeout_ms exceeds credential policy"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use opsgate_core::Result;
    use opsgate_model::credential::CredentialPolicy;

    use super::super::input::{SqlSchemaInput, normalize_input};
    use super::*;

    fn base_input() -> SqlSchemaInput {
        SqlSchemaInput {
            alias: "analytics".to_owned(),
            purpose: "Inspect schema safely".to_owned(),
            database: None,
            mode: String::new(),
            namespace: String::new(),
            table: String::new(),
            limit: None,
            cursor: String::new(),
            max_bytes: None,
            timeout_ms: None,
            include_indexes: false,
        }
    }

    #[test]
    fn policy_rejects_budget_overrides() -> Result<()> {
        let policy = CredentialPolicy {
            max_rows: 10,
            max_bytes: 2048,
            timeout_ms: 1000,
            ..CredentialPolicy::default()
        };
        let input = normalize_input(SqlSchemaInput {
            limit: Some(11),
            ..base_input()
        })?;
        assert!(validate_policy(&policy, &input).is_err());
        let input = normalize_input(SqlSchemaInput {
            limit: Some(10),
            max_bytes: Some(4096),
            ..base_input()
        })?;
        assert!(validate_policy(&policy, &input).is_err());
        let input = normalize_input(SqlSchemaInput {
            limit: Some(10),
            max_bytes: Some(2048),
            timeout_ms: Some(1001),
            ..base_input()
        })?;
        assert!(validate_policy(&policy, &input).is_err());
        Ok(())
    }
}

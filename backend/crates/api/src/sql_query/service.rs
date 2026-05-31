use std::time::Instant;

use opsgate_core::llm_output::validate_json_paths;
use opsgate_core::validation::{trim_required, validate_purpose};
use opsgate_core::{Error, Result};
use opsgate_db::{AuditRepo, CredentialRepo, SqlQueryHistoryRepo};
use opsgate_domain::Caller;
use opsgate_domain::credential::CredentialCategory;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::executor::execute_postgres;
use super::output::SqlQueryOutput;
use super::policy::{enforce_sql_policy, validate_policy_boundary};
use super::recording::{QueryRecorder, record_bad_input};
use crate::audit::runtime::reason;

const DEFAULT_MAX_ROWS: i32 = 100;
const MAX_MAX_ROWS: i32 = 1000;
const DEFAULT_MAX_BYTES: usize = 64 * 1024;
const MIN_MAX_BYTES: usize = 1024;
pub(super) const MAX_MAX_BYTES: usize = 1024 * 1024;
const DEFAULT_TIMEOUT_MS: u32 = 3000;
const MAX_TIMEOUT_MS: u32 = 30000;
const MAX_QUERY_LEN: usize = 16_000;
const MAX_PARAMS: usize = 64;
#[derive(Clone)]
pub(crate) struct SqlQueryService {
    credentials: CredentialRepo,
    history: SqlQueryHistoryRepo,
    audit: AuditRepo,
    sealer: opsgate_core::crypto::Sealer,
    pools: crate::target::pg_pool::TargetPgPools,
}

impl SqlQueryService {
    pub fn new(
        credentials: CredentialRepo,
        history: SqlQueryHistoryRepo,
        audit: AuditRepo,
        sealer: opsgate_core::crypto::Sealer,
        pools: crate::target::pg_pool::TargetPgPools,
    ) -> Self {
        Self {
            credentials,
            history,
            audit,
            sealer,
            pools,
        }
    }

    pub async fn execute(&self, caller: &Caller, input: SqlQueryInput) -> Result<SqlQueryOutput> {
        // Sanitize the raw alias up front: on the bad-input path it is the only
        // request field we record, and it has not been validated yet.
        let raw_alias = crate::audit::safe::message(&input.alias);
        let input = match normalize_input(input) {
            Ok(input) => input,
            Err(error) => {
                record_bad_input(&self.history, &self.audit, caller, &raw_alias, &error).await;
                return Err(error);
            }
        };
        let mut recorder = QueryRecorder::new(&self.history, &self.audit, caller, &input);

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
        recorder.set_credential(&credential);

        if credential.category != CredentialCategory::Sql || credential.provider != "postgres" {
            recorder
                .denied(
                    reason::WRONG_CREDENTIAL_PROVIDER,
                    "credential is not sql/postgres",
                )
                .await;
            return Err(Error::validation(reason::WRONG_CREDENTIAL_PROVIDER));
        }
        if let Err(error) = validate_policy_boundary(&credential.policy, &input) {
            recorder
                .denied(reason::POLICY_DENIED, &error.to_string())
                .await;
            return Err(error);
        }
        if let Err(error) = enforce_sql_policy(&input.query, &credential.policy) {
            recorder
                .denied(reason::POLICY_DENIED, &error.to_string())
                .await;
            return Err(error);
        }
        let secret_ciphertext = match material.secret_ciphertext {
            Some(secret_ciphertext) => secret_ciphertext,
            None => {
                recorder
                    .err(reason::SECRET_DESTROYED, "credential secret is destroyed")
                    .await;
                return Err(Error::validation("credential secret is destroyed"));
            }
        };
        let secret = match crate::sql_common::open_sql_secret(
            &self.sealer,
            &credential.alias,
            &secret_ciphertext,
        ) {
            Ok(secret) => secret,
            Err(error) => {
                recorder
                    .err(reason::SECRET_OPEN_FAILED, "credential secret open failed")
                    .await;
                return Err(error);
            }
        };
        let target = match crate::target::postgres::prepare_postgres_target(
            crate::sql_common::credential_database_url(&credential)?,
            credential.allow_private_network,
            credential.allow_insecure_transport,
        )
        .await
        {
            Ok(target) => target,
            Err(error) => {
                recorder
                    .err(reason::TARGET_PREPARE_FAILED, "target prepare failed")
                    .await;
                return Err(error);
            }
        };

        let started = Instant::now();
        let mut output =
            match execute_postgres(&self.pools, credential.id, &target, &secret, &input).await {
                Ok(output) => output,
                Err(error) => {
                    recorder.err(reason::QUERY_FAILED, "sql query failed").await;
                    return Err(error);
                }
            };
        output.latency_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        recorder.ok(&output).await;
        Ok(output)
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct SqlQueryInput {
    /// Alias from credential.list with category=sql and provider=postgres.
    pub alias: String,
    /// Short human reason for the query; stored in audit/history.
    pub purpose: String,
    /// Read-only SQL. Only SELECT/WITH are allowed. Prefer explicit columns, WHERE, count/group, or keyset pagination; avoid SELECT *.
    pub query: String,
    /// Positional bind parameters for the SQL query.
    #[serde(default)]
    #[schemars(schema_with = "opsgate_core::schema::json_value_array_schema")]
    pub params: Vec<Value>,
    /// 1-3 JSONPath projections to shrink the returned JSON after SQL execution.
    #[serde(default)]
    pub jsonpath: Vec<String>,
    /// Maximum rows to fetch before JSONPath/byte trimming. Prefer narrowing the SQL when possible.
    pub max_rows: Option<i32>,
    /// Response byte budget after SQL shaping and JSONPath projection.
    pub max_bytes: Option<usize>,
    /// Query timeout in milliseconds, bounded by credential policy.
    pub timeout_ms: Option<u32>,
}

#[derive(Debug, Clone)]
pub(super) struct NormalizedInput {
    pub(super) alias: String,
    pub(super) purpose: String,
    pub(super) query: String,
    pub(super) params: Vec<Value>,
    pub(super) jsonpath: Vec<String>,
    pub(super) max_rows: i32,
    pub(super) max_bytes: usize,
    pub(super) timeout_ms: u32,
    pub(super) query_sha256: String,
}

fn normalize_input(input: SqlQueryInput) -> Result<NormalizedInput> {
    let alias = trim_required("alias", &input.alias)?;
    let purpose = validate_purpose(&input.purpose)?;
    let query = input.query.trim().to_owned();
    if query.is_empty() || query.len() > MAX_QUERY_LEN || query.contains('\0') {
        return Err(Error::validation(format!(
            "query must be 1-{MAX_QUERY_LEN} characters without NUL"
        )));
    }
    if input.params.len() > MAX_PARAMS {
        return Err(Error::validation(format!(
            "too many params ({} > {MAX_PARAMS})",
            input.params.len()
        )));
    }
    validate_json_paths(&input.jsonpath)?;
    let max_rows = input.max_rows.unwrap_or(DEFAULT_MAX_ROWS);
    if !(1..=MAX_MAX_ROWS).contains(&max_rows) {
        return Err(Error::validation("max_rows out of range"));
    }
    let max_bytes = input.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    if !(MIN_MAX_BYTES..=MAX_MAX_BYTES).contains(&max_bytes) {
        return Err(Error::validation("max_bytes out of range"));
    }
    let timeout_ms = input.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(Error::validation("timeout_ms out of range"));
    }
    let query_sha256 = sha256_hex(&query);
    Ok(NormalizedInput {
        alias,
        purpose,
        query,
        params: input.params,
        jsonpath: input.jsonpath,
        max_rows,
        max_bytes,
        timeout_ms,
        query_sha256,
    })
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> SqlQueryInput {
        SqlQueryInput {
            alias: "analytics".to_owned(),
            purpose: "Count recent rows".to_owned(),
            query: "select status, count(*) from payments group by status".to_owned(),
            params: Vec::new(),
            jsonpath: Vec::new(),
            max_rows: None,
            max_bytes: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn input_defaults_match_docs() -> Result<()> {
        let input = normalize_input(base_input())?;
        assert!(input.jsonpath.is_empty());
        assert_eq!(input.max_rows, DEFAULT_MAX_ROWS);
        assert_eq!(input.max_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(input.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(input.params.len(), 0);
        Ok(())
    }

    #[test]
    fn input_validation_rejects_docs_boundaries() {
        let mut input = base_input();
        input.query = String::new();
        assert!(normalize_input(input.clone()).is_err());
        input = base_input();
        input.params = vec![Value::Null; MAX_PARAMS + 1];
        assert!(normalize_input(input.clone()).is_err());
        input = base_input();
        input.jsonpath = vec!["status".to_owned()];
        assert!(normalize_input(input.clone()).is_err());
        input = base_input();
        input.max_rows = Some(MAX_MAX_ROWS + 1);
        assert!(normalize_input(input).is_err());
    }
}

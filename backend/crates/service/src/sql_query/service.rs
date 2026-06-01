use std::time::Instant;

use opsgate_core::{Error, Result};
use opsgate_db::{AuditRepo, CredentialRepo, SqlQueryHistoryRepo};
use opsgate_model::Caller;
use opsgate_model::credential::CredentialCategory;

use super::executor::execute_postgres;
use super::input::{SqlQueryInput, normalize_input};
use super::output::SqlQueryOutput;
use super::policy::{enforce_sql_policy, validate_policy_boundary};
use super::recording::{QueryRecorder, record_bad_input};
use crate::audit::runtime::reason;

const SQL_POLICY_DENIED_MESSAGE: &str = "sql query denied by credential policy";

#[derive(Clone)]
pub struct SqlQueryService {
    credentials: CredentialRepo,
    history: SqlQueryHistoryRepo,
    audit: AuditRepo,
    sealer: crate::crypto::Sealer,
    pools: opsgate_infra::postgres_pool::TargetPgPools,
}

impl SqlQueryService {
    pub fn new(
        credentials: CredentialRepo,
        history: SqlQueryHistoryRepo,
        audit: AuditRepo,
        sealer: crate::crypto::Sealer,
        pools: opsgate_infra::postgres_pool::TargetPgPools,
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
        let raw_alias = crate::audit::safe_message(&input.alias);
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
                .denied(reason::POLICY_DENIED, policy_denial_history_message(&error))
                .await;
            return Err(error);
        }
        if let Err(error) = enforce_sql_policy(&input.query, &credential.policy) {
            recorder
                .denied(reason::POLICY_DENIED, policy_denial_history_message(&error))
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
        let target = match opsgate_infra::postgres::prepare_postgres_target(
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
                    let (kind, message) = crate::sql_common::safe_error_record(
                        &error,
                        reason::QUERY_FAILED,
                        "sql query failed",
                    );
                    recorder.err(kind, &message).await;
                    return Err(error);
                }
            };
        output.latency_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        recorder.ok(&output).await;
        Ok(output)
    }
}

fn policy_denial_history_message(_error: &Error) -> &'static str {
    SQL_POLICY_DENIED_MESSAGE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_denial_history_message_does_not_echo_sql_text() {
        let error = Error::validation(
            "query has SQL syntax error: Expected end of statement, found: secret_table",
        );

        let message = policy_denial_history_message(&error);

        assert_eq!(message, "sql query denied by credential policy");
        assert!(!message.contains("secret_table"));
        assert!(!message.contains("Expected"));
    }
}

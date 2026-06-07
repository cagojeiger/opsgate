use opsgate_core::{Error, Result};
use opsgate_db::{ApiCallHistoryRepo, AuditRepo, CredentialRepo};
use opsgate_model::Caller;
use opsgate_model::credential::CredentialCategory;

use crate::audit::runtime::reason;
use crate::credential::secret;
use opsgate_infra::http::TargetHttpClients;
use std::time::Duration;

use super::input::{ApiCallInput, normalize_input};
use super::output::ApiCallOutput;
use super::policy::{ApiPolicyDenial, caller_overrides_secret_header, validate_policy_boundary};
use super::recording::{CallRecorder, record_bad_input};
use super::target::execute_target_call;

const TARGET_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct ApiCallService {
    credentials: CredentialRepo,
    history: ApiCallHistoryRepo,
    audit: AuditRepo,
    sealer: crate::crypto::Sealer,
    target_clients: TargetHttpClients,
}

impl ApiCallService {
    pub fn new(
        credentials: CredentialRepo,
        history: ApiCallHistoryRepo,
        audit: AuditRepo,
        sealer: crate::crypto::Sealer,
    ) -> Result<Self> {
        Ok(Self {
            credentials,
            history,
            audit,
            sealer,
            target_clients: TargetHttpClients::new(TARGET_TIMEOUT)?,
        })
    }

    pub async fn call(&self, caller: &Caller, input: ApiCallInput) -> Result<ApiCallOutput> {
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
        let mut recorder = CallRecorder::new(&self.history, &self.audit, caller, &input);

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
        let secret_ciphertext = material.secret_ciphertext;
        let tls_ca = material.tls_ca;
        recorder.set_credential(&credential);

        if credential.category != CredentialCategory::Http {
            recorder
                .denied(
                    reason::WRONG_CREDENTIAL_CATEGORY,
                    "credential is not category=http",
                )
                .await;
            return Err(Error::validation(reason::WRONG_CREDENTIAL_CATEGORY));
        }
        if let Err(denial) = validate_policy_boundary(&credential, &input) {
            recorder.denied(denial.kind(), denial.message()).await;
            return Err(denial.into_error());
        }

        let secret_ciphertext = match secret_ciphertext {
            Some(secret_ciphertext) => secret_ciphertext,
            None => {
                recorder
                    .err(reason::SECRET_DESTROYED, "credential secret is destroyed")
                    .await;
                return Err(Error::validation("credential secret is destroyed"));
            }
        };
        let secret =
            match secret::open_http_headers(&self.sealer, &credential.alias, &secret_ciphertext) {
                Ok(secret) => secret,
                Err(error) => {
                    recorder
                        .err(reason::SECRET_OPEN_FAILED, "credential secret open failed")
                        .await;
                    return Err(error);
                }
            };
        if caller_overrides_secret_header(secret.iter().map(|header| header.name.as_str()), &input)
        {
            let denial = ApiPolicyDenial::RequestHeaderNotAllowed;
            recorder.denied(denial.kind(), denial.message()).await;
            return Err(denial.into_error());
        }

        let output = match execute_target_call(
            &self.target_clients,
            &credential,
            tls_ca.as_deref(),
            &input,
            &secret,
        )
        .await
        {
            Ok(output) => output,
            Err(error) => {
                recorder.err(error.kind, &error.message).await;
                return Err(error.error);
            }
        };
        recorder.ok(&output).await;
        Ok(output)
    }
}

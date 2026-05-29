//! Credential domain model, policy, and input validation.

mod header;
mod model;
mod policy;
mod validation;

pub use header::{contains_fold, header_blocked, valid_header_name};
pub use model::{
    Credential, CredentialCategory, CredentialListParams, CredentialSecret, InsertCredentialParams,
    RegisterCredentialInput, RegisterHttpCredentialInput, RegisterSqlCredentialInput, SecretHeader,
    UpdateCredentialParams,
};
pub use policy::{CredentialPolicy, normalize_policy_for_category, validate_policy_for_category};
pub use validation::{normalize_register_input, validate_register_input};

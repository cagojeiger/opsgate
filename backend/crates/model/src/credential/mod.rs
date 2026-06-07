//! Credential domain model, policy, and input validation.

mod header;
mod model;
mod policy;
mod validation;

pub use header::{
    contains_fold, header_blocked, valid_header_name,
    validate_allowed_headers_do_not_overlap_secret,
};
pub use model::{
    Credential, CredentialCategory, CredentialListParams, CredentialSecret, CredentialTarget,
    InsertCredentialParams, RegisterCredentialInput, RegisterHttpCredentialInput,
    RegisterSqlCredentialInput, SecretHeader, UpdateCredentialParams,
};
pub use policy::{
    CredentialPolicy, normalize_policy_for_category, request_path_matches_prefix,
    validate_policy_for_category,
};
pub use validation::{
    normalize_register_input, normalize_tags, validate_alias, validate_env,
    validate_postgres_database_url, validate_provider, validate_register_input, validate_tag,
    validate_tags,
};

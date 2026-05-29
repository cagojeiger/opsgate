//! Business domain types and logic.
//!
//! Pure Rust: no HTTP, no sqlx. The api layer maps requests to these types and
//! the db layer persists them.

pub mod credential;
pub mod identity;
pub mod user;

pub use credential::{Credential, CredentialCategory};
pub use identity::{Caller, Channel, IdentityError, ResolveAttrs, Resolver, UserStore};
pub use user::{Role, User};

//! Business domain types and logic.
//!
//! Pure Rust: no HTTP, no sqlx. The api layer maps requests to these types and
//! the db layer persists them.

pub mod identity;
pub mod user;

pub use identity::{Caller, Channel, IdentityError, ResolveAttrs, Resolver, Role, UserStore};
pub use user::User;

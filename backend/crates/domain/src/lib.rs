//! Business domain types and logic.
//!
//! Pure Rust: no HTTP, no sqlx. The api layer maps requests to these types and
//! the db layer persists them. Start putting entities and use-cases here.

pub mod user;

pub use user::User;

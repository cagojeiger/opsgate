//! Infrastructure adapters for credential target access.
//!
//! This crate connects to external systems registered as credentials. It must
//! not depend on the opsgate application database, service layer, or API layer.

pub mod http;
pub mod network_guard;
pub mod postgres;
pub mod postgres_pool;

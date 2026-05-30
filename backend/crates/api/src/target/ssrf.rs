//! Shared SSRF/IP guard helpers.
//!
//! HTTP and Postgres target guard code will move here as the target harness
//! stories progress. The canonical blocked-IP predicate remains
//! `opsgate_core::net::ssrf::is_blocked_target_ip`.

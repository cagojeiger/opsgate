# Rust port parity review

Date: 2026-05-29

Baseline:

```text
Go source repo: /Users/kangheeyong/project/opsgate-jelly
Go baseline commit: 3de72e5
Rust repo: /Users/kangheeyong/project/opsgate
Rust implementation commit reviewed: b0cabb0
```

## Scope

This review compares the Go feature surface against the Rust port by feature
layer, not by internal package structure. The goal is behavioral parity for the
0.1.0 release candidate across auth, MCP, REST, credentials, SQL execution,
audit/history, database privileges, and release smoke checks.

Out of scope unless separately required:

- converting Rust UUID primary keys back to Go BIGSERIAL ids
- rewriting the Rust module layout to mirror Go packages
- adding REST credential update routes that were not present in the Go REST
  surface
- proving production target side effects against real Kubernetes or external
  Postgres instances inside unit tests

## Result

```text
Core feature-layer parity: restored
Release gate: PASS
Remaining differences: documented below
```

The Rust port now has matching role boundaries, OAuth discovery/challenge
metadata, runtime/admin MCP tool separation, REST parity routes, credential
validation and lifecycle history, runtime database least privilege, request
audit metadata, and execution tool boundary behavior for the Go-visible surface.

## Phase Commits

```text
28b597b docs: add Rust port parity execution plan
b210bf3 auth: restore role authorization boundary
31bf145 credentials: restore validation and lifecycle history parity
af5b497 db: restore runtime database least privilege
feef2e9 rest: restore API execution and credential endpoints
4651128 auth: restore OAuth discovery compatibility
25fa837 sql: restore metadata function policy parity
192bcf5 audit: restore auth and request audit parity
f46ed2e docs: update Rust release and smoke checks
de439d9 test: lock MCP tool surface parity
fae6981 auth: match MCP admin denial challenge parity
0aead19 build: add Rust release wrapper
5c78e57 credentials: close final parity validation gaps
b0cabb0 execution: close final tool parity gaps
```

## Feature Matrix

| Layer | Rust status | Evidence |
| --- | --- | --- |
| Identity and role model | Parity restored | `Role` is carried through `Caller`; admin override uses `OPSGATE_ADMIN_EMAIL`; viewer/operator/admin checks are service-level. |
| `/mcp` and `/mcp/admin` | Parity restored | Runtime and admin tool names match the Go smoke contract; non-admin admin access returns the Go-compatible scoped 401 challenge. |
| OAuth metadata and bearer challenge | Parity restored | Authorization-server metadata, root/path protected-resource metadata, and `scope="openid offline_access"` challenge coverage are tested. |
| REST routes | Parity restored | Rust exposes `GET /api/v1/me`, `POST /api/v1/api/call`, `POST /api/v1/sql/query`, credential create/list/delete, with bearer and role tests. |
| Credential lifecycle | Parity restored | Register/update/delete validate Go-visible boundaries, keep secrets out of output, populate actor columns, and write per-alias history. |
| Database runtime privilege | Parity restored | Migration URL and runtime URL are split; `opsgate_app` grants are tested for allowed runtime operations and denied schema/user-role mutation. |
| `api.call` | Parity restored | Endpoint base paths are preserved before appending request paths; policy and secret-header gates are tested; denied calls are audited/history-recorded. |
| `sql.query` | Mostly restored | Role denials and bad input are recorded; JSON array/object params are accepted and bound; AST policy covers metadata/function parity. Remaining result/connection differences are below. |
| `sql.schema` | Mostly restored | Role denials and bad input are audited; metadata output is value-free. Remaining connection guard difference is below. |
| Audit/history | Parity restored for release surface | Auth, request, MCP tool, credential lifecycle, API call, and SQL query paths carry request metadata and avoid secrets. |
| Release/smoke workflow | Parity restored | `Makefile` provides `release-check`, `up`, and `curl-meta`; docs list Rust commands and smoke expectations. |

## Remaining Differences

These are not hidden failures; they are the remaining non-trivial differences
that should be tracked explicitly.

1. SQL private-network guard is pre-connect in Rust, dial-time in Go.

   Go guards Postgres dialing through its pgx dialer path. Rust validates the
   resolved target IPs before connecting, then lets SQLx establish the actual
   connection. That leaves a narrower DNS rebinding or TOCTOU window than the Go
   guarded dial approach. Relevant Rust paths: `backend/crates/api/src/sql_query/service.rs`
   and `backend/crates/api/src/sql_schema/service.rs`. Relevant Go path:
   `opsgate-jelly/internal/service/sql/postgres/dial.go`.

2. SQL result materialization differs.

   Go streams rows from pgx and can use driver field descriptions directly.
   Rust wraps the user query with JSON aggregation and derives output from JSON
   rows after execution. The public envelope is covered by tests, but exact
   driver-level type metadata, duplicate column behavior, and some null/type
   inference edge cases are not identical. Relevant Rust path:
   `backend/crates/api/src/sql_query/service.rs`. Relevant Go path:
   `opsgate-jelly/internal/service/sql/query/execute.go`.

3. MCP SDK wire-level e2e is still absent.

   Rust tests lock exact tool names, route auth/challenge behavior, and schema
   structural sanity. They do not compare full MCP schemas against the Go
   server, and there is no real Streamable HTTP MCP SDK client handshake test
   against a running server yet. This is already called out in
   `docs/mcp/smoke-report.md`.

4. RustSec audit is not part of the release gate.

   `make release-check` covers formatting, checking, tests, clippy, release
   build, and diff whitespace. It does not currently run `cargo audit` or an
   equivalent advisory database check.

5. Primary-key shape differs by design.

   The Rust port keeps UUID ids while the Go source uses integer ids in several
   persistence models. The feature boundary does not expose this as a release
   blocker, and no data-compatibility requirement has been established.

## Verification

Local commands run for the final execution parity pass:

```sh
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
cargo clippy -p opsgate-api --all-targets --all-features -- -D warnings
git diff --check
```

Focused checks run while closing final gaps:

```sh
cargo test -p opsgate-api api_call::service::tests
cargo test -p opsgate-api sql_query::service::tests
cargo test -p opsgate-api sql_schema::service::tests
cargo test -p opsgate-api auth::bearer_tests::rest_parity_routes_enforce_roles
cargo test -p opsgate-api
```

Final release gate:

```sh
make release-check
```

Result:

```text
PASS
```

## Final Assessment

The Rust port is now realistic for the documented 0.1.0 release surface if the
remaining SQL connection/result-materialization differences are accepted as
known follow-up work. The highest-risk unclosed item is the SQL private-network
guard placement; if the release threat model requires Go-equivalent DNS
rebinding resistance for Postgres targets, that item should be fixed before
production exposure of `sql.query` and `sql.schema`.

# MCP smoke report

Date: 2026-05-29

Scope:

```text
/mcp runtime surface
/mcp/admin admin surface
OAuth 2.1 bearer challenge and discovery metadata
runtime/admin tool separation
credential lifecycle tools
api.call JSON envelope and policy gates
sql.schema metadata envelope
sql.query AST/output shape gates
wrong-tool audit/history metadata regression
REST parity routes
```

## Local Test Commands

Use the workspace and focused crate tests for the Rust smoke bundle:

```sh
cargo test -p opsgate-api auth::bearer_tests
cargo test -p opsgate-api auth::metadata::tests
cargo test -p opsgate-api mcp::server::tests
cargo test -p opsgate-api mcp::tools
cargo test -p opsgate-api credential::service::tests
cargo test -p opsgate-api api_call::service::tests
cargo test -p opsgate-api sql_schema::service::tests
cargo test -p opsgate-api sql_query::service::tests
cargo test -p opsgate-db --tests
```

Full release smoke uses:

```sh
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release --bin opsgate-api
git diff --check
```

Result:

```text
PASS
```

## Smoke Contract

```text
/mcp/admin live tool surface:
  credential.delete
  credential.list
  credential.register_http
  credential.register_sql
  credential.update_http
  credential.update_sql
  me

/mcp live tool surface:
  api.call
  credential.list
  me
  sql.schema
  sql.query

REST parity routes require bearer auth and enforce roles:
  GET /api/v1/me
  POST /api/v1/api/call
  POST /api/v1/sql/query
  POST /api/v1/credentials
  GET /api/v1/credentials
  DELETE /api/v1/credentials/{alias}

OAuth discovery and challenges:
  authorization-server metadata is served at /.well-known/oauth-authorization-server
  protected-resource metadata is served at root and path-qualified resource paths
  unauthenticated /mcp and /mcp/admin return scoped WWW-Authenticate challenges

Boundary behavior:
  non-admin bearer cannot use /mcp/admin
  registered operator can reach runtime /mcp
  runtime/admin tool names match the Go smoke contract exactly
  viewer cannot execute api.call/sql.schema/sql.query
  credential.list validates fields, pagination, and filter boundaries
  credential outputs do not expose endpoints or secret material
  api.call and sql.query wrong-tool denials keep safe credential metadata snapshots
  sql.query denies writes, locks, blocked functions, and metadata schemas by policy
  sql.schema returns schema structure without row values
  audit rows carry request metadata without recording secrets or request bodies
```

## Compose Metadata Smoke

Start the stack:

```sh
docker compose up --build -d
```

Probe unauthenticated endpoints:

```sh
curl -fsS http://localhost:9091/health
curl -fsS http://localhost:9091/ready
curl -fsS http://localhost:9091/.well-known/oauth-authorization-server
curl -fsS http://localhost:9091/.well-known/oauth-protected-resource
curl -fsS http://localhost:9091/.well-known/oauth-protected-resource/mcp
curl -i -sS http://localhost:9091/mcp \
  -X POST \
  -H 'content-type: application/json' \
  -d '{}'
curl -i -sS http://localhost:9091/mcp/admin \
  -X POST \
  -H 'content-type: application/json' \
  -d '{}'
```

Expected metadata smoke:

```text
/health returns ok
/ready returns ok after Postgres is healthy and migrations complete
authorization-server metadata includes issuer, auth/token/revocation/device endpoints,
  grant types, PKCE S256, public-client auth methods, scopes, and client metadata support
protected-resource metadata includes the configured resource and authorization server
/mcp and /mcp/admin without bearer return 401 and a challenge with:
  resource_metadata
  scope="openid offline_access"
```

## Live OAuth/MCP Smoke

This step needs a valid external AuthGate account matching
`OPSGATE_ADMIN_EMAIL`.

```sh
open http://localhost:9091/login
```

After signup succeeds, connect an MCP client to:

```text
http://localhost:9091/mcp
```

Runtime smoke expectations:

```text
me returns caller role/capabilities
credential.list returns metadata only
api.call is available for category=http aliases
sql.schema is available for category=sql aliases
sql.query is available for category=sql aliases
```

Admin smoke expectations:

```text
http://localhost:9091/mcp/admin is admin-only
credential.register_http/register_sql create sealed credentials
credential.update_http/update_sql mutate metadata/policy only
credential.delete soft-deletes and cryptoshreds the secret
admin credential outputs do not reveal endpoint URLs, usernames, passwords, or sealed headers
```

## Not Covered By Local Smoke

```text
real Kubernetes or third-party API side effects
real production Postgres query execution
browser UI beyond the one-shot /login callback page
client-specific MCP UX
wire-level MCP SDK client handshake against the running Rust server
```

The Rust smoke currently validates exact tool names, MCP tool schemas,
route-level auth/challenge behavior, and service boundaries through crate tests.
A full MCP SDK Streamable HTTP client e2e test is not present yet.

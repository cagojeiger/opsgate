# 0.1.0 release readiness checklist

Date: 2026-05-29

Current target:

```text
0.1.0 Rust release candidate
```

## Status

```text
release-check: PASS
```

There is no repo-local release wrapper in the Rust port. Run the release check
as the explicit command set below so CI/local failures map directly to a tool
output.

## Required Local Checks

```sh
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release --bin opsgate-api
git diff --check
```

The workspace is pinned by `rust-toolchain.toml` to Rust 1.95.0. These checks
cover formatting, type checking, unit/integration tests, strict linting under
the workspace lint policy, the release binary, and whitespace-safe diffs.

## Optional Postgres-Backed Checks

Several DB tests self-skip when `OPSGATE_TEST_DATABASE_URL` is not set. Run
them against a local Postgres when validating migrations, runtime grants, and
audit persistence:

```sh
docker compose up -d postgres

OPSGATE_TEST_DATABASE_URL=postgres://opsgate:opsgate@localhost:5432/opsgate \
cargo test -p opsgate-db --tests
```

To specifically rehearse the runtime least-privilege split:

```sh
OPSGATE_TEST_DATABASE_MIGRATE_URL=postgres://opsgate:opsgate@localhost:5432/opsgate \
OPSGATE_TEST_DATABASE_URL=postgres://opsgate_app:opsgate_app@localhost:5432/opsgate \
cargo test -p opsgate-db --test runtime_least_privilege -- --nocapture
```

`opsgate_app` is created by the migrations that run through the owner URL above.
Do not point the runtime URL at `opsgate_app` before the owner migration step has
run at least once against that database.

## Compose Smoke

Bring up the Rust stack with the external AuthGate configuration from
`.env.example` / `docker-compose.yml`:

```sh
docker compose up --build -d
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

Expected compose smoke results:

```text
/health returns 200
/ready returns 200 after migrations and DB readiness
/.well-known/oauth-authorization-server returns issuer/token/revocation/device metadata
/.well-known/oauth-protected-resource returns the configured resource
/.well-known/oauth-protected-resource/mcp returns path-qualified resource metadata
unauthenticated /mcp and /mcp/admin return 401 with WWW-Authenticate:
  Bearer resource_metadata="...", scope="openid offline_access"
```

For a live authenticated smoke, open `http://localhost:9091/login` once with the
configured admin account, then connect an MCP client to
`http://localhost:9091/mcp`. Runtime and admin tool surfaces are listed below.

## Verified Surfaces

```text
/mcp runtime:
  me
  credential.list
  api.call
  sql.schema
  sql.query

/mcp/admin:
  me
  credential.register_http
  credential.register_sql
  credential.update_http
  credential.update_sql
  credential.list
  credential.delete

/api/v1 REST:
  GET /api/v1/me
  POST /api/v1/api/call
  POST /api/v1/sql/query
  POST /api/v1/credentials
  GET /api/v1/credentials
  DELETE /api/v1/credentials/{alias}
```

## Remaining Release Notes

```text
No changelog is maintained before the first 0.1.0 release.
Preview pagination/cache remains intentionally out of scope for 0.1.0.
Real target API side effects and live Postgres query execution are environment
smoke checks, not required unit-test gates.
```

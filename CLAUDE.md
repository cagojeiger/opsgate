# opsgate agent notes

## Project shape

- Rust workspace lives under `backend/crates/*`.
- `opsgate-domain` stays pure: no HTTP, sqlx, rmcp, or runtime infrastructure dependencies.
- `opsgate-db` is the Postgres/sqlx adapter crate. It owns migrations, connection setup, and repository implementations for domain ports.
- `opsgate-api` wires HTTP, OAuth/OIDC, Bearer auth, MCP, and route handlers.

## Database / SQLx rules

Use SQLx compile-time checked macros for database queries:

- Prefer `sqlx::query!` / `sqlx::query_as!` over raw `query` / `query_as::<_, T>`.
- Keep SQL values parameterized (`$1`, `$2`, ...) and pass values as macro arguments. Never build SQL with secrets or user input via `format!`.
- Keep `.sqlx/` metadata checked in. This allows `SQLX_OFFLINE=true cargo check` without a live database while preserving compile-time SQL shape checks.
- `.cargo/config.toml` sets `SQLX_OFFLINE=true` for normal local/CI checks.
- After changing migrations or SQL text, refresh metadata against a live dev database:

```bash
SQLX_OFFLINE=false \
DATABASE_URL=postgres://opsgate:opsgate@localhost:5432/opsgate \
cargo sqlx prepare --workspace -- --all-targets
```

Then run:

```bash
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Migration rules

- Treat applied migrations as immutable. Do not edit a migration that may already exist in a persisted DB volume; add a new migration instead.
- For local prototype resets only, `docker compose down -v` may be used to drop the dev database volume.
- Keep migration files in `backend/crates/db/migrations/`.

## Auth / MCP rules

- Bearer verification is shared by REST and MCP through the `verify_bearer` seam.
- MCP and REST `me` output must share the same builder in `api/src/me.rs`.
- Do not log Bearer tokens, OAuth codes, PKCE verifiers, client secrets, or Authorization headers.

## Documentation note

- Do not update `docs/*` unless explicitly asked; current docs may describe future/prototype surfaces.

# opsgate

Monorepo: a Rust backend (Axum + Tokio + sqlx + PostgreSQL) with a Next.js
frontend to follow.

## Layout

```
opsgate/
├─ Cargo.toml              # workspace root (shared deps, lints, profiles)
├─ rust-toolchain.toml     # pinned to Rust 1.95.0
├─ backend/crates/
│  ├─ api/                 # bin: Axum server, routes, HTTP errors
│  ├─ domain/              # pure business logic (no HTTP / no sqlx)
│  ├─ db/                  # sqlx pool + migrations
│  └─ core/                # config + shared error type
├─ backend/Dockerfile      # cargo-chef multi-stage, non-root Debian runtime
├─ docker-compose.yml      # postgres + api (hardened)
└─ frontend/               # Next.js (later)
```

## Local development

```sh
# 1. Start Postgres
docker compose up -d postgres

# 2. Configure env
cp .env.example .env

# 3. Run the API (migrations run on startup)
cargo run --bin opsgate-api
```

Health checks:

```sh
curl localhost:9091/health   # liveness
curl localhost:9091/ready    # readiness (pings the database)
```

Auth/MCP local defaults are configured in `.env.example`:

- `OPSGATE_AUTHGATE_URL=https://authgate.project-jelly.io`
- `OPSGATE_PUBLIC_URL=http://localhost:9091` (builds first-time `login_url`)
- `OPSGATE_OAUTH_CLIENT_ID=opsgate-web`
- `OPSGATE_OAUTH_REDIRECT_URL=http://localhost:9091/callback`
- `OPSGATE_RESOURCE_URL=http://localhost:9091/mcp` (MCP URL/audience)

First-time MCP users must open `${OPSGATE_PUBLIC_URL}/login` once to create the
local opsgate user row, then reconnect the MCP client to `OPSGATE_RESOURCE_URL`.

## Checks

```sh
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
cargo clippy --all-targets --all-features -- -D warnings
```

Release and MCP smoke details are tracked in
`docs/release-checklist.md` and `docs/mcp/smoke-report.md`.

## Full stack via Docker

```sh
docker compose up --build
```

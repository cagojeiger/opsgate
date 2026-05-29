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
├─ Dockerfile              # cargo-chef multi-stage, non-root alpine
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
curl localhost:8080/health   # liveness
curl localhost:8080/ready    # readiness (pings the database)
```

## Checks

```sh
cargo fmt --all
cargo clippy --all-targets
cargo test
```

## Full stack via Docker

```sh
docker compose up --build
```

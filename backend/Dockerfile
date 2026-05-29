# syntax=docker/dockerfile:1.7

FROM rust:1.95.0-bookworm AS chef

WORKDIR /app
# Native toolchain for crates with C build scripts, plus certificates for Cargo HTTPS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        cmake \
        g++ \
        make \
        perl \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN rustup component add rustfmt clippy rust-src
RUN --mount=type=cache,id=opsgate-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=opsgate-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    cargo install cargo-chef --locked \
    && cargo install sccache --locked --no-default-features

ENV RUSTC_WRAPPER=sccache \
    SCCACHE_DIR=/sccache \
    CARGO_INCREMENTAL=0

FROM chef AS planner

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY backend ./backend
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json
# sqlx query! macros are checked against the cached metadata, not a live DB.
ENV SQLX_OFFLINE=true
RUN --mount=type=cache,id=opsgate-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=opsgate-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=opsgate-sccache,target=/sccache,sharing=locked \
    --mount=type=cache,id=opsgate-target-release,target=/app/target,sharing=locked \
    cargo chef cook --release --locked --recipe-path recipe.json
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .sqlx ./.sqlx
COPY backend ./backend
RUN --mount=type=cache,id=opsgate-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=opsgate-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=opsgate-sccache,target=/sccache,sharing=locked \
    --mount=type=cache,id=opsgate-target-release,target=/app/target,sharing=locked \
    cargo build --release --locked --bin opsgate-api \
    && cp /app/target/release/opsgate-api /usr/local/bin/opsgate-api

FROM debian:bookworm-slim AS runtime

COPY --from=chef /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin appuser
WORKDIR /app
COPY --from=builder /usr/local/bin/opsgate-api /usr/local/bin/opsgate-api

ENV BIND_ADDR=0.0.0.0:9091
EXPOSE 9091

USER appuser
ENTRYPOINT ["/usr/local/bin/opsgate-api"]

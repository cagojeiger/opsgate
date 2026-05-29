FROM rust:1.95.0-alpine3.22 AS chef

WORKDIR /app
# musl-dev for linking; cmake/make/g++/perl in case a TLS backend needs to build C.
RUN apk add --no-cache musl-dev cmake make g++ perl
RUN cargo install cargo-chef --locked

FROM chef AS planner

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY backend ./backend
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json
# sqlx query! macros are checked against the cached metadata, not a live DB.
ENV SQLX_OFFLINE=true
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY backend ./backend
RUN cargo build --release --locked --bin opsgate-api

FROM alpine:3.22 AS runtime

RUN addgroup -S app && adduser -S -D -H -u 10001 -G app appuser
WORKDIR /app
COPY --from=builder /app/target/release/opsgate-api /usr/local/bin/opsgate-api

ENV BIND_ADDR=0.0.0.0:9091
EXPOSE 9091

USER appuser
ENTRYPOINT ["/usr/local/bin/opsgate-api"]

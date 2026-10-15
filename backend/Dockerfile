# syntax=docker/dockerfile:1.7

# Stage 1: shared Rust build toolbox.
#
# This stage installs system build tools, cargo-chef, and sccache once. The
# later planner/builder stages inherit from it so dependency planning and final
# compilation use the exact same Rust/toolchain environment.
#
# We use Debian instead of Alpine to avoid musl-specific surprises and to keep
# Rust crate builds close to the runtime libc.
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

# Stage 2: dependency graph planner.
#
# cargo-chef reads manifests/source layout and emits recipe.json. The recipe
# changes only when dependency-relevant inputs change, so Docker can reuse the
# expensive dependency build layer when application code changes.
FROM chef AS planner

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY backend ./backend
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: dependency cache + application build.
#
# First cook dependencies from recipe.json, then copy the real source and build
# the opsgate-api binary. BuildKit cache mounts keep Cargo registry/git data,
# sccache objects, and target artifacts outside the image layers but reusable
# across local Docker builds.
FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json
# sqlx query! / query_as! macros are checked against committed `.sqlx`
# metadata, not a live DB. This keeps Docker builds reproducible.
ENV SQLX_OFFLINE=true
RUN --mount=type=cache,id=opsgate-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=opsgate-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=opsgate-sccache,target=/sccache,sharing=locked \
    --mount=type=cache,id=opsgate-target-release,target=/app/target,sharing=locked \
    cargo chef cook --release --locked --recipe-path recipe.json
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
# Required by SQLX_OFFLINE=true.
COPY .sqlx ./.sqlx
COPY backend ./backend
RUN --mount=type=cache,id=opsgate-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=opsgate-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=opsgate-sccache,target=/sccache,sharing=locked \
    --mount=type=cache,id=opsgate-target-release,target=/app/target,sharing=locked \
    cargo build --release --locked --bin opsgate-api \
    && cp /app/target/release/opsgate-api /usr/local/bin/opsgate-api

# The GNU Rust binary needs glibc, libm and libgcc_s. Distroless cc supplies
# these libraries and /etc/ssl/certs/ca-certificates.crt without a runtime shell.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2 AS runtime-base

# Keep the existing passwd/group identity: SQLx uses the OS username when a
# Postgres DSN omits it. Prepare the text files in a stage that has a shell.
FROM chef AS runtime-identity
COPY --from=runtime-base /etc/passwd /tmp/runtime-passwd
COPY --from=runtime-base /etc/group /tmp/runtime-group
RUN printf '%s\n' 'appuser:x:10001:10001::/nonexistent:/usr/sbin/nologin' >> /tmp/runtime-passwd \
    && printf '%s\n' 'app:x:10001:' >> /tmp/runtime-group

FROM runtime-base AS runtime
COPY --from=runtime-identity /tmp/runtime-passwd /etc/passwd
COPY --from=runtime-identity /tmp/runtime-group /etc/group
WORKDIR /app
COPY --from=builder /usr/local/bin/opsgate-api /usr/local/bin/opsgate-api

ENV OPSGATE_BIND_ADDR=0.0.0.0:9091
EXPOSE 9091

USER 10001:10001
ENTRYPOINT ["/usr/local/bin/opsgate-api"]

# Start with image that has the Rust toolchain installed
FROM rust:1.77-alpine AS chef
USER root
# Add cargo-chef to cache dependencies
RUN apk add --no-cache musl-dev & cargo install cargo-chef

FROM chef AS planner
# Capture info needed to build dependencies
WORKDIR /macros
COPY ./macros/ .
RUN cargo chef prepare --recipe-path recipe.json
WORKDIR /app
COPY ./auth-service .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
WORKDIR /macros
COPY --from=planner /macros/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json

# Build application
COPY ./auth-service .
ENV SQLX_OFFLINE=true
RUN cargo build --release --bin auth-service

# We do not need the Rust toolchain to run the binary!
# Start with a minimal image and copy over the binary and assets folder.
FROM debian:buster-slim AS runtime
WORKDIR /app
COPY --from=builder /app/target/release/auth-service /usr/local/bin
COPY --from=builder /app/assets /app/assets
ENV REDIS_HOST_NAME=redis
ENTRYPOINT ["/usr/local/bin/auth-service"]

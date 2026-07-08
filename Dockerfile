FROM rust:1.96-slim-trixie AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Pre-compile dependencies before copying real source.
COPY Cargo.toml Cargo.lock ./
ENV SQLX_OFFLINE=true

RUN mkdir -p src && echo 'fn main(){}' > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy real source and rebuild
COPY .sqlx .sqlx
COPY src src
COPY migrations migrations
RUN find src -type f -exec touch {} + && cargo build --release

# Runtime stage
FROM debian:trixie-slim AS prod
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/sabf /usr/local/bin/sabf

RUN useradd -m -u 1000 sabf
USER sabf
EXPOSE 80
HEALTHCHECK --interval=10s --timeout=3s --start-period=2s --retries=3 \
    CMD curl -f http://localhost:${PORT:-80}/health || exit 1
CMD ["sabf"]

# ---- dev (source mounted at runtime, cargo run on start) ----
# Usage: build with --target dev, mount ./src, Cargo.toml, Cargo.lock as volumes.
# Named volume on /app/target persists compiled deps across restarts.
FROM rust:1.96-slim-trixie AS dev
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev curl && rm -rf /var/lib/apt/lists/*
EXPOSE 80
HEALTHCHECK --interval=10s --timeout=3s --start-period=120s --retries=3 \
    CMD addr="${LISTEN_ADDR:-0.0.0.0:80}"; curl -f http://localhost:${addr##*:}/health || exit 1
CMD ["cargo", "run", "-p", "sabf"]

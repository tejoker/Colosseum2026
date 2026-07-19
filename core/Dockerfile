# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.88-bookworm AS builder

WORKDIR /app

# Cache dependencies first
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    mkdir -p src/bin && echo "fn main() {}" > src/bin/client.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Build the actual project
COPY src/ src/
RUN cargo build --release

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl python3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/sauron-core .
COPY --from=builder /app/target/release/client ./client
COPY seed.sh .

# Non-root runtime user. /app is writable for the default DATABASE_PATH
# (./sauron.db); /var/lib/sauronid is the volume mount point used by the
# compose files, pre-created so named volumes inherit app ownership.
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin app && \
    mkdir -p /var/lib/sauronid && \
    chown -R app:app /app /var/lib/sauronid

ENV PORT=3001
EXPOSE 3001

USER app

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=6 \
    CMD curl -fsS http://localhost:3001/healthz || exit 1

CMD ["./sauron-core"]

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33 AS builder

WORKDIR /app

# Fetch exactly the dependency graph committed for this release. A missing or
# stale lockfile is a hard build failure.
COPY Cargo.toml Cargo.lock ./
RUN cargo fetch --locked

# Build the actual project
COPY src/ src/
RUN cargo build --locked --release

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

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

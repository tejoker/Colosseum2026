# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33 AS builder

WORKDIR /app

# The build context is the REPOSITORY ROOT, not core/. core's manifest resolves
# a path dependency at ../transparent-zk/types, which a core/-scoped context
# cannot see — `cargo fetch --locked` then fails outright and no image is ever
# produced. Every compose file passes `context: <repo root>` with
# `dockerfile: core/Dockerfile`; keep them in step with this file.
COPY core/Cargo.toml core/Cargo.lock ./core/
COPY transparent-zk/types ./transparent-zk/types
# src/ must be in place before any cargo invocation: with only a manifest,
# cargo aborts with "no targets specified in the manifest", so the old
# manifest-only `cargo fetch` dependency-cache layer could never have worked.
COPY core/src ./core/src

WORKDIR /app/core

# --locked: build exactly the dependency graph committed for this release. A
# missing or stale lockfile is a hard build failure.
RUN cargo build --locked --release

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl python3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/core/target/release/sauron-core .
COPY --from=builder /app/core/target/release/client ./client
# The receipt/audit chain verifier ships with the runtime image: it is meant to
# be run by whoever holds the database, including a customer checking the
# operator, and `verify-receipts` needs no key at all.
COPY --from=builder /app/core/target/release/sauronid-cli ./sauronid-cli
COPY core/seed.sh .

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

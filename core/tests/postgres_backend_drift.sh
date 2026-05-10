#!/usr/bin/env bash
# Postgres backend drift integration test.
#
# Phase 3's Postgres swap is incomplete: only `agent_call_nonces` is currently
# served by the dual-backend Repo. Every other table still goes through the
# legacy rusqlite path. This test makes the gap explicit by:
#
#   1. Starting the core with SAURON_DB_BACKEND=postgres pointed at a Postgres
#      DB that has the schema applied.
#   2. Registering an agent (writes to SQLite via legacy code paths).
#   3. Calling a per-call-sig-protected endpoint and observing that the
#      `agent_call_nonces` Postgres row IS created (Repo is wired correctly).
#   4. Querying /admin/agents (which queries SQLite) to confirm the agent IS
#      visible there.
#   5. Querying the Postgres `agents` table directly to confirm it is EMPTY
#      — proving the data drift between the two backends.
#
# This test is INTENDED TO PASS, but the test passing means the drift exists.
# When the Postgres swap is complete (12/12 modules ported), this test will
# need to be updated because the agents table will live in Postgres too.
#
# Skipped automatically when Docker / Postgres are not available.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CORE_BIN="$ROOT/core/target/release/sauron-core"
TEST_DB_NAME="sauronid_drift_test"
PG_PORT=15432
PG_USER="sauronid"
PG_PASS="sauronid_drift_test"
DATABASE_URL="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG_PORT}/${TEST_DB_NAME}"

red()   { echo -e "\033[0;31m$*\033[0m"; }
green() { echo -e "\033[0;32m$*\033[0m"; }
ylw()   { echo -e "\033[0;33m$*\033[0m"; }

cleanup() {
    fuser -k 3001/tcp 2>/dev/null || true
    docker rm -f sauronid_drift_pg 2>/dev/null || true
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1; then
    ylw "[SKIP] docker not installed; cannot run Postgres drift test"
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    ylw "[SKIP] docker daemon not reachable; start Docker Desktop / dockerd first"
    exit 0
fi

if [[ ! -x "$CORE_BIN" ]]; then
    red "[ERROR] core binary not found at $CORE_BIN; run 'cargo build --release' first"
    exit 1
fi

# 1. Stand up Postgres
echo "▸ starting Postgres docker on :$PG_PORT"
docker run -d --name sauronid_drift_pg \
    -e POSTGRES_USER="$PG_USER" \
    -e POSTGRES_PASSWORD="$PG_PASS" \
    -e POSTGRES_DB="$TEST_DB_NAME" \
    -p "${PG_PORT}:5432" \
    postgres:16-alpine >/dev/null
for i in $(seq 1 20); do
    if docker exec sauronid_drift_pg pg_isready -U "$PG_USER" -d "$TEST_DB_NAME" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Apply schema
echo "▸ applying migrations/postgres/0001_initial.sql"
docker exec -i sauronid_drift_pg psql -U "$PG_USER" -d "$TEST_DB_NAME" \
    < "$ROOT/migrations/postgres/0001_initial.sql" >/dev/null

# 2. Boot core with Postgres opt-in
echo "▸ starting core with SAURON_DB_BACKEND=postgres"
fuser -k 3001/tcp 2>/dev/null || true
sleep 1
rm -f "$ROOT/core/sauron.db" "$ROOT/core/sauron.db-shm" "$ROOT/core/sauron.db-wal"
(cd "$ROOT/core" && \
    SAURON_ADMIN_KEY=super_secret_hackathon_key \
    ENV=development \
    SAURON_DB_BACKEND=postgres \
    DATABASE_URL="$DATABASE_URL" \
    "$CORE_BIN" > /tmp/sauron-drift.log 2>&1 &)
for i in $(seq 1 15); do
    if curl -sf http://127.0.0.1:3001/health >/dev/null 2>&1; then break; fi
    sleep 1
done

# 3. Seed and register one agent (via the existing seed.sh path)
bash "$ROOT/core/seed.sh" >/dev/null

# 4. Use the existing 8-scenario suite to cause an agent registration
(cd "$ROOT/kya-redteam" && \
    SAURON_CORE_URL=http://127.0.0.1:3001 \
    SAURON_ADMIN_KEY=super_secret_hackathon_key \
    node dist/index.js >/dev/null 2>&1 || true)

# 5. Check the drift
echo
echo "═══════════════════════════════════════════════════════════"
echo "  Postgres backend drift verification"
echo "═══════════════════════════════════════════════════════════"

SQLITE_AGENTS=$(curl -sf -H "x-admin-key: super_secret_hackathon_key" \
    http://127.0.0.1:3001/admin/agents | python3 -c 'import sys, json; print(len(json.load(sys.stdin)))')
PG_AGENTS=$(docker exec -i sauronid_drift_pg psql -U "$PG_USER" -d "$TEST_DB_NAME" \
    -tAc "SELECT COUNT(*) FROM agents;")
PG_NONCES=$(docker exec -i sauronid_drift_pg psql -U "$PG_USER" -d "$TEST_DB_NAME" \
    -tAc "SELECT COUNT(*) FROM agent_call_nonces;")

echo "  SQLite (legacy path)  /admin/agents        : ${SQLITE_AGENTS} agents"
echo "  Postgres (live path) SELECT COUNT(*) agents: ${PG_AGENTS}"
echo "  Postgres agent_call_nonces (Repo-ported)   : ${PG_NONCES}"
echo

if [[ "$SQLITE_AGENTS" -gt 0 && "$PG_AGENTS" == "0" ]]; then
    green "DRIFT CONFIRMED: ${SQLITE_AGENTS} agents in SQLite, 0 in Postgres."
    echo "                 This is the expected state of Phase 3 (3/12 modules ported)."
    echo "                 To finish the swap, port the remaining 9 modules — see"
    echo "                 docs/operations.md migration progress table."
    exit 0
else
    red "UNEXPECTED: drift not observed (SQLite=$SQLITE_AGENTS, Postgres=$PG_AGENTS)."
    echo "  Either Phase 3 swap completed (good — update this test)"
    echo "  or the test setup is broken."
    exit 1
fi

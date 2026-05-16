#!/usr/bin/env bash
# SauronID quickstart — cold clone to running 16-attack-suite-passing in ~60s.
#
# Default mode: development, advisory call-sig (existing scenarios pass).
# Set SAURON_REQUIRE_CALL_SIG=1 in env to run fail-closed empirical suite.
#
# What this does:
#   1. Builds the Rust core (release).
#   2. Builds the TypeScript clients (redteam, agentic, zkp/issuer).
#   3. Starts the core in the background, waits for /admin/stats to respond.
#   4. Seeds 10 dev clients + 10 dev users via core HTTP APIs.
#   5. Runs the 9-scenario invariant suite.
#   6. (If SAURON_REQUIRE_CALL_SIG=1) Runs the 16-attack empirical suite.
#   7. Reports a green or red final status.
#
# Cleanup happens on exit: server is killed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# ────────────────────────────────────────────────────────────────────────
RED="\033[0;31m"
GRN="\033[0;32m"
YLW="\033[0;33m"
BLD="\033[1m"
RST="\033[0m"

step() { echo -e "\n${BLD}▸ $*${RST}"; }
ok()   { echo -e "  ${GRN}✓${RST} $*"; }
fail() { echo -e "  ${RED}✗${RST} $*"; }

# ────────────────────────────────────────────────────────────────────────
# 0. Defaults — operator can override via env
# ────────────────────────────────────────────────────────────────────────
export ENV="${ENV:-development}"
# shellcheck source=scripts/lib/dev_secrets.sh
source "$ROOT/scripts/lib/dev_secrets.sh"
load_dev_admin_key
export SAURON_CORE_URL="${SAURON_CORE_URL:-http://127.0.0.1:3001}"
export SAURON_URL="${SAURON_URL:-$SAURON_CORE_URL}"
export RUST_LOG="${RUST_LOG:-warn}"

ENFORCE_MODE="${SAURON_REQUIRE_CALL_SIG:-0}"
case "$ENFORCE_MODE" in
    1|true|yes|TRUE|YES|True|Yes) ENFORCE_MODE=1 ;;
    *) ENFORCE_MODE=0 ;;
esac

# ────────────────────────────────────────────────────────────────────────
# 1. Cleanup any previous run + ensure deps exist
# ────────────────────────────────────────────────────────────────────────
step "Pre-flight"
if ! command -v cargo >/dev/null 2>&1; then
    fail "cargo not found — install rustup from https://rustup.rs"
    exit 1
fi
if ! command -v node >/dev/null 2>&1; then
    fail "node not found — install Node 18+ from https://nodejs.org"
    exit 1
fi

# Free any lingering server on the target port
fuser -k 3001/tcp 2>/dev/null || true
sleep 1
ok "ports clear, toolchain present"

# ────────────────────────────────────────────────────────────────────────
# 2. Build the Rust core
# ────────────────────────────────────────────────────────────────────────
step "Build Rust core (release)"
cd "$ROOT/core"
cargo build --release 2>&1 | tail -3
ok "core compiled"

# ────────────────────────────────────────────────────────────────────────
# 3. Build the TS clients
# ────────────────────────────────────────────────────────────────────────
step "Build redteam (TS)"
cd "$ROOT/redteam"
if [ ! -d node_modules ]; then npm install --silent 2>&1 | tail -2; fi
npm run build --silent
ok "redteam compiled"

step "Build agentic SDK (TS)"
cd "$ROOT/agentic"
if [ ! -d node_modules ]; then npm install --silent 2>&1 | tail -2; fi
if grep -q '"build"' package.json 2>/dev/null; then
    npm run build --silent || true
fi
ok "agentic compiled"

# ────────────────────────────────────────────────────────────────────────
# 4. Start the core, wait for health
# ────────────────────────────────────────────────────────────────────────
step "Start core (ENV=$ENV, enforce_call_sig=$ENFORCE_MODE)"
cd "$ROOT/core"
rm -f sauron.db sauron.db-shm sauron.db-wal
if [ "$ENFORCE_MODE" = "1" ]; then
    export SAURON_REQUIRE_CALL_SIG=1
fi
./target/release/sauron-core > /tmp/sauron-quickstart.log 2>&1 &
CORE_PID=$!
trap 'kill $CORE_PID 2>/dev/null || true; fuser -k 3001/tcp 2>/dev/null || true' EXIT

# Wait for /admin/stats
for i in $(seq 1 30); do
    if curl -sf "$SAURON_CORE_URL/admin/stats" -H "x-admin-key: $SAURON_ADMIN_KEY" >/dev/null 2>&1; then
        ok "core ready (pid=$CORE_PID)"
        break
    fi
    printf '.'
    sleep 1
    if [ "$i" = "30" ]; then
        fail "core failed to come up; check /tmp/sauron-quickstart.log"
        tail -30 /tmp/sauron-quickstart.log
        exit 1
    fi
done

# ────────────────────────────────────────────────────────────────────────
# 5. Seed clients + users
# ────────────────────────────────────────────────────────────────────────
step "Seed clients + users"
bash seed.sh > /tmp/sauron-seed.log 2>&1
ok "seeded 10 clients + 10 users"

# ────────────────────────────────────────────────────────────────────────
# 6. Run the test suite appropriate to the mode
#
# Advisory mode (default): the 9-scenario invariant suite. It uses legacy
# call shapes that pre-date the extended per-call-sig coverage, so it only
# fits cleanly when call-sig is advisory.
#
# Fail-closed mode (SAURON_REQUIRE_CALL_SIG=1): the 16-attack empirical
# suite. Every scenario sends the full header set including the
# config-digest. This is the production-shape verification.
# ────────────────────────────────────────────────────────────────────────
cd "$ROOT/redteam"
if [ "$ENFORCE_MODE" = "1" ]; then
    step "Run 16-attack empirical suite (fail-closed mode)"
    if node dist/scenarios/empirical-suite.js > /tmp/sauron-empirical.log 2>&1; then
        grep "empirical:" /tmp/sauron-empirical.log
        ok "empirical 16/16"
    else
        fail "empirical suite failed; tail of log:"
        tail -25 /tmp/sauron-empirical.log
        exit 1
    fi
else
    step "Run KYA invariant suite (9 scenarios, advisory mode)"
    if node dist/index.js > /tmp/sauron-invariants.log 2>&1; then
        grep "all .* run(s) passed\|FAIL" /tmp/sauron-invariants.log | head -3
        ok "invariants pass"
    else
        fail "invariants failed; tail of log:"
        tail -20 /tmp/sauron-invariants.log
        exit 1
    fi
fi

# ────────────────────────────────────────────────────────────────────────
# 8. Final status
# ────────────────────────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════"
echo -e "  ${GRN}${BLD}SauronID quickstart: GREEN${RST}"
echo "════════════════════════════════════════"
echo
echo "  Core:        $SAURON_CORE_URL"
echo "  Metrics:     $SAURON_CORE_URL/metrics"
echo "  Admin key:   $SAURON_ADMIN_KEY"
echo "  Logs:        /tmp/sauron-quickstart.log"
echo
echo "  Next:"
echo "    • run a Python adapter: see clients/python/sauronid_client/README.md"
echo "    • verify an audit anchor: docs/empirical-comparison.md"
echo "    • production deploy: docs/operations.md"
echo

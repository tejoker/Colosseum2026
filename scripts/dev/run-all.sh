#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=scripts/lib/dev_secrets.sh
source "$ROOT/scripts/lib/dev_secrets.sh"
load_dev_admin_key
export SAURON_ISSUER_SHARED_SECRET="${SAURON_ISSUER_SHARED_SECRET:-sauron_issuer_shared_dev_key_change_me}"

step() { printf '\n[run-all] %s\n' "$*"; }

install_if_needed() {
  local dir="$1"
  if [[ ! -d "${dir}/node_modules" ]]; then
    (cd "$dir" && npm install --silent)
  fi
}

step "core cargo test + binaries"
(cd "$ROOT/core" && cargo test && cargo build --bins)

step "dev leash demo smoke"
"$ROOT/core/tests/smoke_dev_leash_demo.sh"

step "zkp issuer build + tests"
install_if_needed "$ROOT/zkp/issuer"
(cd "$ROOT/zkp/issuer" && npm run build && npm test)

step "agentic sdk build + tests"
install_if_needed "$ROOT/agentic"
(cd "$ROOT/agentic" && npm run build && npm test)

step "redteam build"
install_if_needed "$ROOT/redteam"
(cd "$ROOT/redteam" && npm run build)

step "dashboard lint + build"
install_if_needed "$ROOT/dashboard"
(cd "$ROOT/dashboard" && npm run lint && npm run build)

step "core confidence suite with leash e2e + redteam"
CONF_SHARED_ITERS="${CONF_SHARED_ITERS:-1}" \
CONF_MIGRATION_ITERS="${CONF_MIGRATION_ITERS:-1}" \
CONF_RESTART_ITERS="${CONF_RESTART_ITERS:-1}" \
CONF_MATRIX_AGENT_TYPES="${CONF_MATRIX_AGENT_TYPES:-claude,openai}" \
"$ROOT/core/tests/run_confidence_suite.sh"

step "all checks passed"

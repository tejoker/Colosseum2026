#!/usr/bin/env bash
# One-command demo bring-up. Run from the deploy/ directory on the VM.
#
#   cp .env.deploy.example .env   # then edit .env
#   ./setup-solana.sh             # if SAURON_SOLANA_ENABLED=1
#   ./deploy.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

compose_file="docker-compose.deploy.yml"

if [[ ! -f .env ]]; then
  echo "FATAL: no .env. Copy .env.deploy.example to .env and fill it in." >&2
  exit 1
fi

# docker compose (v2) or legacy docker-compose.
if docker compose version >/dev/null 2>&1; then
  dc=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  dc=(docker-compose)
else
  echo "FATAL: docker compose not found. Install Docker Engine + compose plugin." >&2
  exit 1
fi

# Warn (don't block) if Solana is on but the keypair is missing.
if grep -qE '^SAURON_SOLANA_ENABLED=1' .env && [[ ! -f secrets/solana-devnet.json ]]; then
  echo "WARNING: SAURON_SOLANA_ENABLED=1 but secrets/solana-devnet.json is missing." >&2
  echo "         Run ./setup-solana.sh first, or set SAURON_SOLANA_ENABLED=0." >&2
fi

echo "==> Building images"
"${dc[@]}" -f "$compose_file" --env-file .env build

echo "==> Starting stack"
"${dc[@]}" -f "$compose_file" --env-file .env up -d

echo
echo "==> Up. Give Caddy ~30s to obtain TLS certs, then:"
# shellcheck disable=SC1091
set -a; . ./.env; set +a
echo "    core API : https://${CORE_DOMAIN}/health"
echo "    dashboard: https://${DASH_DOMAIN}  (basic-auth user: ${DASH_USER})"
echo
echo "Logs:   ${dc[*]} -f $compose_file logs -f"
echo "Stop:   ${dc[*]} -f $compose_file down"

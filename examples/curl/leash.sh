#!/usr/bin/env bash
# SauronID leash from pure curl: health, dev registration, session login,
# and a denied-vs-allowed admin call showing the 4xx error envelope.
#
# Prereqs: `docker compose up` at the repo root (core on localhost:3001,
# dev endpoints enabled, fixed dev admin key). Do NOT reuse this key
# anywhere near production.
set -euo pipefail

CORE_URL="${CORE_URL:-http://localhost:3001}"
ADMIN_KEY="dev-only-admin-key-not-for-production"
EMAIL="leash-demo-$(date +%s)@sauron.dev"
PASSWORD="pass_demo"

step() { printf '\n== %s ==\n' "$1"; }

step "1. Health check (no auth)"
curl -s "$CORE_URL/healthz"
echo

step "2. Register a user via the dev endpoint (SAURON_ENABLE_DEV_ENDPOINTS=1)"
curl -s "$CORE_URL/dev/register_user" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"Monzo\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",
       \"first_name\":\"Leash\",\"last_name\":\"Demo\",
       \"date_of_birth\":\"1990-01-01\",\"nationality\":\"FR\"}"
echo

step "3. Log in -> tenant-bound session + the owner's key image"
curl -s "$CORE_URL/user/auth" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"
echo

step "4. Denied: admin route without credentials (note the error envelope)"
# 4xx responses use {"error":{"code","message","fix"}}; some legacy
# handlers still return plain text.
curl -s -w '\nHTTP %{http_code}\n' "$CORE_URL/admin/stats"

step "5. Allowed: same route with the dev admin key"
curl -s -w '\nHTTP %{http_code}\n' "$CORE_URL/admin/stats" \
  -H "x-admin-key: $ADMIN_KEY" | head -c 400
echo

step "6. Denied: agent token mint without a user session"
curl -s -w '\nHTTP %{http_code}\n' "$CORE_URL/agent/token" \
  -H 'content-type: application/json' \
  -d '{"agent_id":"agt_nonexistent","ttl_secs":60}'

# Signed agent calls (call-sig v2) need the Ed25519 PoP key generated at
# registration -- that is what the SDKs are for. See ../python-quickstart.
printf '\nDone. Next: examples/python-quickstart for the signed-call flow.\n'

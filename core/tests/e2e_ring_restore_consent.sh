#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../../scripts/lib/dev_secrets.sh
source "${ROOT_DIR}/../scripts/lib/dev_secrets.sh"
load_dev_admin_key
PORT="${E2E_PORT:-3311}"
API_URL="${API_URL:-http://127.0.0.1:${PORT}}"
E2E_ISSUER_URL="${E2E_ISSUER_URL:-http://127.0.0.1:4000}"
ADMIN_KEY="$SAURON_ADMIN_KEY"
DB_PATH="${E2E_DB_PATH:-/tmp/sauron-ring-restore-${USER:-user}-$$.db}"
LOG_PATH="${E2E_LOG_PATH:-/tmp/sauron-ring-restore-${USER:-user}-$$.log}"
BANK_SITE="${E2E_BANK_SITE:-RestartBank}"
RETAIL_SITE="${E2E_RETAIL_SITE:-RestartRetail}"

# shellcheck source=tests/lib/zkp_fixture.sh
source "${ROOT_DIR}/tests/lib/zkp_fixture.sh"
# shellcheck source=tests/lib/agent_action.sh
source "${ROOT_DIR}/tests/lib/agent_action.sh"
ensure_zkp_fixture_bundle
zkp_require_issuer

SERVER_PID=""

json_get() {
  local key="$1"
  python3 -c 'import json,sys
key=sys.argv[1]
raw=sys.stdin.read()
try:
  obj=json.loads(raw)
except Exception:
  print("")
  sys.exit(0)
cur=obj
for part in key.split("."):
  if isinstance(cur, dict):
    cur=cur.get(part)
  else:
    cur=None
    break
print(json.dumps(cur) if isinstance(cur,(dict,list)) else ("" if cur is None else cur))' "$key"
}

cleanup() {
  if [[ -n "${SERVER_PID}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${tmp_pop_json:-}" ]]; then
    rm -f "${tmp_pop_json}"
  fi
  rm -f "${DB_PATH}" "${DB_PATH}-wal" "${DB_PATH}-shm"
}
trap cleanup EXIT

ensure_binary() {
  if [[ -x "${ROOT_DIR}/target/debug/sauron-core" ]]; then
    echo "${ROOT_DIR}/target/debug/sauron-core"
    return
  fi
  (cd "${ROOT_DIR}" && cargo build --bins >/dev/null)
  if [[ -x "${ROOT_DIR}/target/debug/sauron-core" ]]; then
    echo "${ROOT_DIR}/target/debug/sauron-core"
  else
    echo "Failed to build sauron-core binary" >&2
    exit 1
  fi
}

start_server() {
  local binary="$1"
  ENV=development \
  SAURON_ADMIN_KEY="${ADMIN_KEY}" \
  SAURON_ISSUER_URL="${E2E_ISSUER_URL}" \
  SAURON_ISSUER_SHARED_SECRET="${SAURON_ISSUER_SHARED_SECRET:-sauron_issuer_shared_dev_key_change_me}" \
  DATABASE_PATH="${DB_PATH}" \
  PORT="${PORT}" \
  "${binary}" >"${LOG_PATH}" 2>&1 &
  SERVER_PID="$!"
  for _ in $(seq 1 90); do
    if curl -sf "${API_URL}/admin/stats" -H "x-admin-key: ${ADMIN_KEY}" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  echo "Server failed to start. Log:" >&2
  tail -n 80 "${LOG_PATH}" >&2 || true
  exit 1
}

stop_server() {
  if [[ -n "${SERVER_PID}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
    SERVER_PID=""
  fi
}

ensure_client() {
  local name="$1"
  local ctype="$2"
  curl -sS -X POST "${API_URL}/admin/clients" \
    -H "x-admin-key: ${ADMIN_KEY}" \
    -H 'content-type: application/json' \
    -d "{\"name\":\"${name}\",\"client_type\":\"${ctype}\"}" >/dev/null
}

BINARY="$(ensure_binary)"

rand_suffix=$(python3 - <<'PY'
import time, random
print(f"{int(time.time())}{random.randint(1000,9999)}")
PY
)
email="restart_${rand_suffix}@sauron.local"
password="Passw0rd!${rand_suffix}"

printf '[E2E restart] boot #1\n'
start_server "${BINARY}"

ensure_client "${BANK_SITE}" "BANK"
ensure_client "${RETAIL_SITE}" "ZKP_ONLY"

curl -sS -X POST "${API_URL}/dev/buy_tokens" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"${RETAIL_SITE}\",\"amount\":4}" >/dev/null

register_res=$(curl -sS -X POST "${API_URL}/dev/register_user" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"${BANK_SITE}\",\"email\":\"${email}\",\"password\":\"${password}\",\"first_name\":\"Ring\",\"last_name\":\"Restore\",\"date_of_birth\":\"1990-01-01\",\"nationality\":\"FRA\"}")
user_pub=$(printf '%s' "${register_res}" | json_get "public_key_hex")
if [[ -z "${user_pub}" ]]; then
  echo "dev/register_user failed: ${register_res}" >&2
  exit 1
fi

auth_res=$(curl -sS -X POST "${API_URL}/user/auth" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"${email}\",\"password\":\"${password}\"}")
session=$(printf '%s' "${auth_res}" | json_get "session")
key_image=$(printf '%s' "${auth_res}" | json_get "key_image")
if [[ -z "${session}" || -z "${key_image}" ]]; then
  echo "user/auth failed: ${auth_res}" >&2
  exit 1
fi

tmp_pop_json=$(mktemp)
create_pop_key_file "$tmp_pop_json"
pop_public_key_b64u=$(pop_public_key_b64u_from_file "$tmp_pop_json")
pop_jkt="e2e-restart-pop-${rand_suffix}"
agent_keys=$(agent_action_keygen)
agent_public_key_hex=$(printf '%s' "$agent_keys" | json_get "public_key_hex")
agent_secret_hex=$(printf '%s' "$agent_keys" | json_get "secret_hex")
agent_ring_key_image_hex=$(printf '%s' "$agent_keys" | json_get "ring_key_image_hex")
agent_res=$(curl -sS -X POST "${API_URL}/agent/register" \
  -H 'content-type: application/json' \
  -H "x-sauron-session: ${session}" \
  -d "{\"human_key_image\":\"${key_image}\",\"agent_checksum\":\"sha256:restart-${rand_suffix}\",\"intent_json\":\"{\\\"scope\\\":[\\\"kyc_consent\\\",\\\"prove_age\\\"]}\",\"public_key_hex\":\"${agent_public_key_hex}\",\"ring_key_image_hex\":\"${agent_ring_key_image_hex}\",\"pop_jkt\":\"${pop_jkt}\",\"pop_public_key_b64u\":\"${pop_public_key_b64u}\",\"ttl_secs\":3600}")
ajwt=$(printf '%s' "${agent_res}" | json_get "ajwt")
agent_id=$(printf '%s' "${agent_res}" | json_get "agent_id")
assurance=$(printf '%s' "${agent_res}" | json_get "assurance_level")
if [[ -z "${ajwt}" || -z "${agent_id}" || "${assurance}" != "delegated_bank" ]]; then
  echo "agent/register failed or assurance mismatch: ${agent_res}" >&2
  exit 1
fi

printf '[E2E restart] restart core\n'
stop_server
start_server "${BINARY}"

req_res=$(curl -sS -X POST "${API_URL}/kyc/request" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"${RETAIL_SITE}\",\"requested_claims\":[\"age_over_threshold\",\"age_threshold\"]}")
request_id=$(printf '%s' "${req_res}" | json_get "request_id")
if [[ -z "${request_id}" ]]; then
  echo "kyc/request failed: ${req_res}" >&2
  exit 1
fi

consent_token_res=$(issue_agent_token "$session" "$agent_id" 300)
consent_ajwt=$(printf '%s' "$consent_token_res" | json_get "ajwt")
pop_json=$(fresh_pop_jws "$session" "$agent_id" "$tmp_pop_json")
pop_challenge_id=$(printf '%s' "$pop_json" | json_get "pop_challenge_id")
pop_jws=$(printf '%s' "$pop_json" | json_get "pop_jws")
consent_action=$(sign_agent_action "$agent_secret_hex" "$agent_id" "$key_image" "kyc_consent" "kyc_consent:${request_id}" "$RETAIL_SITE" 0 "" "$consent_ajwt")
consent_body=$(python3 - "$consent_ajwt" "$RETAIL_SITE" "$request_id" "$pop_challenge_id" "$pop_jws" "$consent_action" <<'PY'
import json, sys
ajwt, site, request_id, pop_id, pop_jws, action = sys.argv[1:]
print(json.dumps({
  "ajwt": ajwt,
  "site_name": site,
  "request_id": request_id,
  "pop_challenge_id": pop_id,
  "pop_jws": pop_jws,
  "agent_action": json.loads(action),
}, separators=(",", ":")))
PY
)
consent_res=$(curl -sS -X POST "${API_URL}/agent/kyc/consent" \
  -H 'content-type: application/json' \
  -d "${consent_body}")
consent_token=$(printf '%s' "${consent_res}" | json_get "consent_token")
if [[ -z "${consent_token}" ]]; then
  echo "agent/kyc/consent after restart failed: ${consent_res}" >&2
  exit 1
fi

retrieve_body="$(zkp_build_retrieve_payload_json "${consent_token}" "${RETAIL_SITE}" "prove_age")"
retrieve_token_res=$(issue_agent_token "$session" "$agent_id" 300)
retrieve_ajwt=$(printf '%s' "$retrieve_token_res" | json_get "ajwt")
retrieve_action=$(sign_agent_action "$agent_secret_hex" "$agent_id" "$key_image" "prove_age" "kyc_retrieve:${RETAIL_SITE}" "$RETAIL_SITE" 0 "" "$retrieve_ajwt")
retrieve_body="$(merge_agent_action_json "${retrieve_body}" "${retrieve_action}")"
retrieve_res=$(curl -sS -X POST "${API_URL}/kyc/retrieve" \
  -H 'content-type: application/json' \
  -H "x-agent-ajwt: ${retrieve_ajwt}" \
  -d "${retrieve_body}")
trust=$(printf '%s' "${retrieve_res}" | json_get "identity.trust_verified")
agent_ring=$(printf '%s' "${retrieve_res}" | json_get "identity.agent_in_agent_ring")
if [[ "${trust}" != "True" && "${trust}" != "true" ]]; then
  echo "retrieve trust verification failed: ${retrieve_res}" >&2
  exit 1
fi
if [[ "${agent_ring}" != "True" && "${agent_ring}" != "true" ]]; then
  echo "retrieve agent ring verification failed after restart: ${retrieve_res}" >&2
  exit 1
fi

echo "[PASS] ring restore + delegated consent survives restart"

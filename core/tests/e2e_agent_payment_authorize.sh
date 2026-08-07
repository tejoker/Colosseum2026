#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:3001}"
BANK_SITE="${E2E_BANK_SITE:-BNP Paribas}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../../scripts/lib/dev_secrets.sh
source "${ROOT_DIR}/../scripts/lib/dev_secrets.sh"
require_admin_key
ADMIN_KEY="$SAURON_ADMIN_KEY"

# shellcheck source=tests/lib/agent_action.sh
source "${ROOT_DIR}/tests/lib/agent_action.sh"

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

ensure_client() {
  local name="$1"
  local ctype="$2"
  curl -sS -X POST "${API_URL}/admin/clients" \
    -H "x-admin-key: ${ADMIN_KEY}" \
    -H 'content-type: application/json' \
    -d "{\"name\":\"${name}\",\"client_type\":\"${ctype}\"}" >/dev/null || true
}

rand_suffix=$(python3 - <<'PY'
import time, random
print(f"{int(time.time())}{random.randint(1000,9999)}")
PY
)

email="pay_${rand_suffix}@sauron.local"
password="Passw0rd!${rand_suffix}"
merchant_ok="mrc_ok_${rand_suffix}"
merchant_bad="mrc_bad_${rand_suffix}"
payment_ref="payref_${rand_suffix}"

ensure_client "${BANK_SITE}" "BANK"

printf '[E2E payment-auth] register user\n'
register_res=$(curl -sS -X POST "${API_URL}/dev/register_user" \
  -H 'content-type: application/json' \
  -d "{\"site_name\":\"${BANK_SITE}\",\"email\":\"${email}\",\"password\":\"${password}\",\"first_name\":\"Pay\",\"last_name\":\"Flow\",\"date_of_birth\":\"1990-01-01\",\"nationality\":\"FRA\"}")
user_pub=$(printf '%s' "$register_res" | json_get "public_key_hex")
if [[ -z "$user_pub" ]]; then
  echo "register_user failed: $register_res" >&2
  exit 1
fi

printf '[E2E payment-auth] auth user\n'
auth_res=$(curl -sS -X POST "${API_URL}/user/auth" -H 'content-type: application/json' \
  -d "{\"email\":\"${email}\",\"password\":\"${password}\"}")
session=$(printf '%s' "$auth_res" | json_get "session")
key_image=$(printf '%s' "$auth_res" | json_get "key_image")
if [[ -z "$session" || -z "$key_image" ]]; then
  echo "user_auth failed: $auth_res" >&2
  exit 1
fi

tmp_pop_json=$(mktemp)
create_pop_key_file "$tmp_pop_json"
pop_public_key_b64u=$(pop_public_key_b64u_from_file "$tmp_pop_json")
if [[ -z "$pop_public_key_b64u" ]]; then
  echo "failed to generate pop_public_key_b64u" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi
# RFC 7638 thumbprint of the OKP key above, matching
# crypto_protocol::ed25519_jwk_thumbprint. /agent/register rejects any other
# value ("pop_jkt must be the RFC 7638 thumbprint of pop_public_key_b64u"), so a
# made-up label here failed the test before it sent a single payment request.
pop_jkt=$(python3 - "$pop_public_key_b64u" <<'PY'
import base64, hashlib, sys
x = sys.argv[1].strip()
canonical = '{"crv":"Ed25519","kty":"OKP","x":"%s"}' % x
print(base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).decode().rstrip("="))
PY
)

agent_keys=$(agent_action_keygen)
agent_public_key_hex=$(printf '%s' "$agent_keys" | json_get "public_key_hex")
agent_secret_hex=$(printf '%s' "$agent_keys" | json_get "secret_hex")
agent_ring_key_image_hex=$(printf '%s' "$agent_keys" | json_get "ring_key_image_hex")
if [[ -z "$agent_public_key_hex" || -z "$agent_secret_hex" || -z "$agent_ring_key_image_hex" ]]; then
  echo "agent-action-tool keygen failed: $agent_keys" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi

intent_json=$(python3 - "$merchant_ok" <<'PY'
import json,sys
merchant=sys.argv[1]
print(json.dumps({
  "scope":["payment_initiation","payment_consume"],
  "maxAmount":12.34,
  "currency":"EUR",
  "constraints":{"merchant_allowlist":[merchant]}
}, separators=(',', ':')))
PY
)

printf '[E2E payment-auth] register pop-enabled agent\n'
agent_res=$(curl -sS -X POST "${API_URL}/agent/register" \
  -H 'content-type: application/json' \
  -H "x-sauron-session: ${session}" \
  -d "{\"human_key_image\":\"${key_image}\",\"agent_checksum\":\"sha256:pay-${rand_suffix}\",\"intent_json\":$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$intent_json"),\"public_key_hex\":\"${agent_public_key_hex}\",\"ring_key_image_hex\":\"${agent_ring_key_image_hex}\",\"pop_jkt\":\"${pop_jkt}\",\"pop_public_key_b64u\":\"${pop_public_key_b64u}\",\"ttl_secs\":3600}")
ajwt=$(printf '%s' "$agent_res" | json_get "ajwt")
agent_id=$(printf '%s' "$agent_res" | json_get "agent_id")

# Sign the /agent/action/challenge calls this script makes. The route requires a
# per-call signature (default-deny across /agent/*); the PoP private key is the
# "d" member of the JWK generated above, and the config digest is the checksum
# the server computed at registration.
SAURON_E2E_POP_SECRET_B64U=$(python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["private_jwk"]["d"])
' "$tmp_pop_json")
SAURON_E2E_CONFIG_DIGEST=$(curl -sS "${API_URL}/agent/${agent_id}" | json_get "agent_checksum")
SAURON_E2E_AGENT_ID="${agent_id}"
export SAURON_E2E_POP_SECRET_B64U SAURON_E2E_CONFIG_DIGEST SAURON_E2E_AGENT_ID
if [[ -z "$ajwt" || -z "$agent_id" ]]; then
  echo "agent/register failed: $agent_res" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi

printf '[E2E payment-auth] deny over maxAmount\n'
pop_json=$(fresh_pop_jws "$session" "$agent_id" "$tmp_pop_json")
pop_challenge_id=$(printf '%s' "$pop_json" | json_get "pop_challenge_id")
pop_jws=$(printf '%s' "$pop_json" | json_get "pop_jws")
agent_action_over=$(sign_agent_action "$agent_secret_hex" "$agent_id" "$key_image" "payment_initiation" "${payment_ref}_over" "$merchant_ok" 1235 "EUR" "$ajwt")
body_over="$(merge_agent_action_json "{\"ajwt\":\"${ajwt}\",\"amount_minor\":1235,\"currency\":\"EUR\",\"merchant_id\":\"${merchant_ok}\",\"payment_ref\":\"${payment_ref}_over\",\"pop_challenge_id\":\"${pop_challenge_id}\",\"pop_jws\":\"${pop_jws}\"}" "$agent_action_over")"
build_sig_args POST /agent/payment/authorize "$body_over"
code_over=$(printf '%s' "$body_over" | curl -sS -o /tmp/pay_auth_over.json -w '%{http_code}' -X POST "${API_URL}/agent/payment/authorize" -H 'content-type: application/json' "${SIG_ARGS[@]}" -d @-)
if [[ "$code_over" == "200" ]]; then
  echo "over-limit payment authorization should fail: $(cat /tmp/pay_auth_over.json)" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi

printf '[E2E payment-auth] deny non-allowlisted merchant\n'
pop_json=$(fresh_pop_jws "$session" "$agent_id" "$tmp_pop_json")
pop_challenge_id2=$(printf '%s' "$pop_json" | json_get "pop_challenge_id")
pop_jws2=$(printf '%s' "$pop_json" | json_get "pop_jws")
agent_action_merchant=$(sign_agent_action "$agent_secret_hex" "$agent_id" "$key_image" "payment_initiation" "${payment_ref}_merchant" "$merchant_bad" 1000 "EUR" "$ajwt")
body_merchant="$(merge_agent_action_json "{\"ajwt\":\"${ajwt}\",\"amount_minor\":1000,\"currency\":\"EUR\",\"merchant_id\":\"${merchant_bad}\",\"payment_ref\":\"${payment_ref}_merchant\",\"pop_challenge_id\":\"${pop_challenge_id2}\",\"pop_jws\":\"${pop_jws2}\"}" "$agent_action_merchant")"
build_sig_args POST /agent/payment/authorize "$body_merchant"
code_merchant=$(printf '%s' "$body_merchant" | curl -sS -o /tmp/pay_auth_merchant.json -w '%{http_code}' -X POST "${API_URL}/agent/payment/authorize" -H 'content-type: application/json' "${SIG_ARGS[@]}" -d @-)
if [[ "$code_merchant" == "200" ]]; then
  echo "merchant-allowlist check should fail: $(cat /tmp/pay_auth_merchant.json)" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi

printf '[E2E payment-auth] authorize valid charge\n'
pop_json=$(fresh_pop_jws "$session" "$agent_id" "$tmp_pop_json")
pop_challenge_id3=$(printf '%s' "$pop_json" | json_get "pop_challenge_id")
pop_jws3=$(printf '%s' "$pop_json" | json_get "pop_jws")
agent_action_ok=$(sign_agent_action "$agent_secret_hex" "$agent_id" "$key_image" "payment_initiation" "${payment_ref}" "$merchant_ok" 1234 "EUR" "$ajwt")
body_ok="$(merge_agent_action_json "{\"ajwt\":\"${ajwt}\",\"amount_minor\":1234,\"currency\":\"EUR\",\"merchant_id\":\"${merchant_ok}\",\"payment_ref\":\"${payment_ref}\",\"pop_challenge_id\":\"${pop_challenge_id3}\",\"pop_jws\":\"${pop_jws3}\"}" "$agent_action_ok")"
build_sig_args POST /agent/payment/authorize "$body_ok"
code_ok=$(printf '%s' "$body_ok" | curl -sS -o /tmp/pay_auth_ok.json -w '%{http_code}' -X POST "${API_URL}/agent/payment/authorize" -H 'content-type: application/json' "${SIG_ARGS[@]}" -d @-)
if [[ "$code_ok" != "200" ]]; then
  echo "valid payment authorization should succeed: $(cat /tmp/pay_auth_ok.json)" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi
authorization_id=$(cat /tmp/pay_auth_ok.json | json_get "authorization_id")
authorization_receipt=$(cat /tmp/pay_auth_ok.json | json_get "action_receipt")
if [[ -z "$authorization_id" ]]; then
  echo "missing authorization_id in success payload: $(cat /tmp/pay_auth_ok.json)" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi

# A "merchant consume with receipt + leash" stage used to sit here, posting to
# /merchant/payment/consume. That route was deliberately removed in d6d5a64
# ("no more kyc + PoNP") and nothing replaced it, so the stage had been posting
# into a 404 — the empty response body is why this test reported
# "merchant consume should succeed:" with no detail. The authorization stages
# above still cover the leash (cap, merchant allowlist, valid charge); if a
# consume endpoint comes back, restore this stage with it.

printf '[E2E payment-auth] deny replayed A-JWT (JTI)\n'
pop_json=$(fresh_pop_jws "$session" "$agent_id" "$tmp_pop_json")
pop_challenge_id4=$(printf '%s' "$pop_json" | json_get "pop_challenge_id")
pop_jws4=$(printf '%s' "$pop_json" | json_get "pop_jws")
agent_action_replay=$(sign_agent_action "$agent_secret_hex" "$agent_id" "$key_image" "payment_initiation" "${payment_ref}_replay" "$merchant_ok" 500 "EUR" "$ajwt")
body_replay="$(merge_agent_action_json "{\"ajwt\":\"${ajwt}\",\"amount_minor\":500,\"currency\":\"EUR\",\"merchant_id\":\"${merchant_ok}\",\"payment_ref\":\"${payment_ref}_replay\",\"pop_challenge_id\":\"${pop_challenge_id4}\",\"pop_jws\":\"${pop_jws4}\"}" "$agent_action_replay")"
build_sig_args POST /agent/payment/authorize "$body_replay"
code_replay=$(printf '%s' "$body_replay" | curl -sS -o /tmp/pay_auth_replay.json -w '%{http_code}' -X POST "${API_URL}/agent/payment/authorize" -H 'content-type: application/json' "${SIG_ARGS[@]}" -d @-)
if [[ "$code_replay" == "200" ]]; then
  echo "replayed ajwt should fail: $(cat /tmp/pay_auth_replay.json)" >&2
  rm -f "$tmp_pop_json"
  exit 1
fi

rm -f "$tmp_pop_json"
echo "[PASS] strict agent payment authorization e2e"

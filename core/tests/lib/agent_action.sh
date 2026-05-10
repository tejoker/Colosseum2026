#!/usr/bin/env bash

agent_action_root_dir() {
  if [[ -n "${ROOT_DIR:-}" ]]; then
    printf '%s' "$ROOT_DIR"
  else
    cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
  fi
}

ensure_agent_action_tool() {
  local root
  root="$(agent_action_root_dir)"
  AGENT_ACTION_TOOL="${AGENT_ACTION_TOOL:-${root}/target/debug/agent-action-tool}"
  if [[ ! -x "${AGENT_ACTION_TOOL}" ]]; then
    (cd "${root}" && cargo build --quiet --bin agent-action-tool)
  fi
}

agent_action_keygen() {
  ensure_agent_action_tool
  "${AGENT_ACTION_TOOL}" keygen
}

ajwt_claim() {
  local token="$1"
  local claim="$2"
  python3 - "$token" "$claim" <<'PY'
import base64, json, sys
token, claim = sys.argv[1], sys.argv[2]
try:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    obj = json.loads(base64.urlsafe_b64decode(payload.encode()))
    value = obj.get(claim, "")
    print(json.dumps(value) if isinstance(value, (dict, list)) else value)
except Exception:
    print("")
PY
}

issue_agent_token() {
  local session="$1"
  local agent_id="$2"
  local ttl="${3:-300}"
  curl -sS -X POST "${API_URL}/agent/token" \
    -H 'content-type: application/json' \
    -H "x-sauron-session: ${session}" \
    -d "{\"agent_id\":\"${agent_id}\",\"ttl_secs\":${ttl}}"
}

sign_agent_action() {
  local secret_hex="$1"
  local agent_id="$2"
  local human_key_image="$3"
  local action="$4"
  local resource="$5"
  local merchant_id="$6"
  local amount_minor="$7"
  local currency="$8"
  local ajwt="$9"
  local ttl="${10:-120}"
  local jti
  jti="$(ajwt_claim "${ajwt}" jti)"
  if [[ -z "${jti}" ]]; then
    echo "unable to read A-JWT jti" >&2
    return 1
  fi
  ensure_agent_action_tool
  local challenge
  challenge=$(python3 - "$agent_id" "$human_key_image" "$action" "$resource" "$merchant_id" "$amount_minor" "$currency" "$jti" "$ttl" <<'PY' | curl -sS -X POST "${API_URL}/agent/action/challenge" -H 'content-type: application/json' -d @-
import json, sys
agent_id, human, action, resource, merchant, amount, currency, jti, ttl = sys.argv[1:]
print(json.dumps({
    "agent_id": agent_id,
    "human_key_image": human,
    "action": action,
    "resource": resource,
    "merchant_id": merchant,
    "amount_minor": int(amount),
    "currency": currency,
    "ajwt_jti": jti,
    "ttl_secs": int(ttl),
}, separators=(",", ":")))
PY
)
  if [[ -z "${challenge}" || "${challenge}" != *'"envelope"'* ]]; then
    echo "agent/action/challenge failed: ${challenge}" >&2
    return 1
  fi
  "${AGENT_ACTION_TOOL}" sign-challenge --secret-hex "${secret_hex}" --challenge-json "${challenge}"
}

merge_agent_action_json() {
  local body_json="$1"
  local proof_json="$2"
  python3 - "$body_json" "$proof_json" <<'PY'
import json, sys
body = json.loads(sys.argv[1])
body["agent_action"] = json.loads(sys.argv[2])
print(json.dumps(body, separators=(",", ":")))
PY
}

create_pop_key_file() {
  local out_path="$1"
  node - "$out_path" <<'NODE'
const crypto = require("crypto");
const fs = require("fs");
const outPath = process.argv[2];
const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
const publicJwk = publicKey.export({ format: "jwk" });
const privateJwk = privateKey.export({ format: "jwk" });
fs.writeFileSync(outPath, JSON.stringify({
  pop_public_key_b64u: publicJwk.x,
  private_jwk: privateJwk
}));
NODE
}

pop_public_key_b64u_from_file() {
  local pop_file="$1"
  python3 - "$pop_file" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["pop_public_key_b64u"])
PY
}

sign_pop_jws_from_file() {
  local pop_file="$1"
  local challenge_payload="$2"
  node - "$pop_file" "$challenge_payload" <<'NODE'
const crypto = require("crypto");
const fs = require("fs");
const inputPath = process.argv[2];
const challenge = process.argv[3];
const pop = JSON.parse(fs.readFileSync(inputPath, "utf8"));
const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).toString("base64url");
const payload = Buffer.from(challenge, "utf8").toString("base64url");
const signingInput = `${header}.${payload}`;
const privateKey = crypto.createPrivateKey({ key: pop.private_jwk, format: "jwk" });
const signature = crypto.sign(null, Buffer.from(signingInput), privateKey).toString("base64url");
process.stdout.write(`${signingInput}.${signature}`);
NODE
}

fresh_pop_jws() {
  local session="$1"
  local agent_id="$2"
  local pop_file="$3"
  local pop_challenge_res pop_challenge_id challenge pop_jws
  pop_challenge_res=$(curl -sS -X POST "${API_URL}/agent/pop/challenge" \
    -H 'content-type: application/json' \
    -H "x-sauron-session: ${session}" \
    -d "{\"agent_id\":\"${agent_id}\"}")
  pop_challenge_id=$(printf '%s' "${pop_challenge_res}" | json_get "pop_challenge_id")
  challenge=$(printf '%s' "${pop_challenge_res}" | json_get "challenge")
  if [[ -z "${pop_challenge_id}" || -z "${challenge}" ]]; then
    echo "agent/pop/challenge failed: ${pop_challenge_res}" >&2
    return 1
  fi
  pop_jws=$(sign_pop_jws_from_file "${pop_file}" "${challenge}")
  python3 - "$pop_challenge_id" "$pop_jws" <<'PY'
import json, sys
print(json.dumps({"pop_challenge_id": sys.argv[1], "pop_jws": sys.argv[2]}, separators=(",", ":")))
PY
}

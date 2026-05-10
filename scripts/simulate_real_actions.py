"""End-to-end real action-receipt simulation.

This is the FULL agent-binding flow that produces real `agent_action_receipts`
rows in the SauronID core. Unlike `simulate_agents.py` (which only registers
agents and writes egress logs), this script exercises:

  - /user/auth                  human session
  - /agent/register             agent + ring keys + PoP key  (server-computed checksum)
  - /agent/token                A-JWT
  - /agent/pop/challenge        one-time PoP challenge
  - /agent/action/challenge     canonical envelope          [per-call signed]
  - agent-action-tool sign-challenge   ring signature over canonical
  - /agent/payment/authorize    full proof: A-JWT + PoP JWS + ring sig + per-call sig
                                → INSERT INTO agent_action_receipts
  - /admin/anchor/agent-actions/run    fires merkle batch onto BTC + Solana

Each successful payment_authorize produces ONE row in `agent_action_receipts`.
Those rows are the leaves of the next anchor batch.

Run:
    python3 scripts/simulate_real_actions.py [--n-actions 2]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from typing import Any

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization

CORE_URL = os.getenv("SAURON_CORE_URL", "http://127.0.0.1:3001")
ADMIN_KEY = os.getenv("SAURON_ADMIN_KEY", "super_secret_hackathon_key")
AGENT_ACTION_TOOL = os.getenv(
    "SAURONID_AGENT_ACTION_TOOL",
    "/home/nicolasbigeard/hackeurope-24/core/target/release/agent-action-tool",
)


# ─── Encoding helpers ───────────────────────────────────────────────

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def now_ms() -> int:
    return int(time.time() * 1000)


# ─── Per-call signature (DPoP-style, what require_call_signature checks) ──

def sign_call_headers(
    sk: Ed25519PrivateKey, agent_id: str, config_digest: str,
    method: str, path: str, body_bytes: bytes,
) -> dict[str, str]:
    ts = now_ms()
    nonce = secrets.token_hex(16)
    body_hash_hex = hashlib.sha256(body_bytes).hexdigest()
    payload = f"{method.upper()}|{path}|{body_hash_hex}|{ts}|{nonce}".encode("utf-8")
    sig = sk.sign(payload)
    return {
        "x-sauron-agent-id": agent_id,
        "x-sauron-call-ts": str(ts),
        "x-sauron-call-nonce": nonce,
        "x-sauron-call-sig": b64u(sig),
        "x-sauron-agent-config-digest": config_digest,
    }


# ─── PoP JWS over a one-time challenge string ────────────────────────

def make_pop_jws(sk: Ed25519PrivateKey, challenge: str) -> str:
    header = b64u(json.dumps({"alg": "EdDSA", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64u(challenge.encode("utf-8"))
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = sk.sign(signing_input)
    return f"{header}.{payload}.{b64u(sig)}"


# ─── Ring keys via agent-action-tool ─────────────────────────────────

def keygen_ring() -> dict[str, str]:
    out = subprocess.run(
        [AGENT_ACTION_TOOL, "keygen"],
        check=True, capture_output=True, text=True,
    ).stdout
    return json.loads(out)


def sign_ring_challenge(secret_hex: str, challenge_json: str) -> dict[str, Any]:
    out = subprocess.run(
        [AGENT_ACTION_TOOL, "sign-challenge",
         "--secret-hex", secret_hex,
         "--challenge-json", challenge_json],
        check=True, capture_output=True, text=True,
    ).stdout
    return json.loads(out)


# ─── HTTP helpers ───────────────────────────────────────────────────

def post_json(path: str, body: dict, headers: dict | None = None) -> requests.Response:
    h = {"content-type": "application/json"}
    if headers:
        h.update(headers)
    return requests.post(f"{CORE_URL}{path}", headers=h,
                         data=json.dumps(body, separators=(",", ":")), timeout=15)


def admin_get(path: str) -> Any:
    r = requests.get(f"{CORE_URL}{path}",
                     headers={"x-admin-key": ADMIN_KEY}, timeout=10)
    r.raise_for_status()
    return r.json()


def admin_post(path: str) -> Any:
    r = requests.post(f"{CORE_URL}{path}",
                      headers={"x-admin-key": ADMIN_KEY}, timeout=30)
    r.raise_for_status()
    return r.json()


# ─── Flow steps ─────────────────────────────────────────────────────

def step_user_auth(email: str, password: str) -> tuple[str, str]:
    r = post_json("/user/auth", {"email": email, "password": password})
    r.raise_for_status()
    j = r.json()
    return j["session"], j["key_image"]


def step_register_agent(
    session: str, human_ki: str,
    ring_pub_hex: str, ring_ki_hex: str,
    pop_pub_b64u: str, pop_jkt: str,
) -> tuple[str, str, str]:
    """Returns (agent_id, agent_checksum, intent_json_used)."""
    intent = {
        "scope": ["payment_initiation"],
        "maxAmount": 100.0,                 # 100.00 EUR cap
        "currency": "EUR",
        "constraints": {
            "merchant_allowlist": ["mch_demo_payments"],
        },
    }
    intent_json = json.dumps(intent, separators=(",", ":"))
    body = {
        "human_key_image": human_ki,
        "agent_type": "llm",
        "checksum_inputs": {
            "model_id": "claude-opus-4-7",
            "system_prompt": f"sim agent {time.time()}",
            "tools": ["search", "pay"],
        },
        "agent_checksum": "",                # server computes
        "intent_json": intent_json,
        "public_key_hex": ring_pub_hex,
        "ring_key_image_hex": ring_ki_hex,
        "pop_jkt": pop_jkt,
        "pop_public_key_b64u": pop_pub_b64u,
        "ttl_secs": 3600,
    }
    r = post_json("/agent/register", body, {"x-sauron-session": session})
    if not r.ok:
        raise RuntimeError(f"register_agent failed: HTTP {r.status_code} {r.text}")
    agent_id = r.json()["agent_id"]
    rec = requests.get(f"{CORE_URL}/agent/{agent_id}", timeout=10)
    rec.raise_for_status()
    return agent_id, rec.json()["agent_checksum"], intent_json


def step_issue_ajwt(session: str, agent_id: str) -> tuple[str, str]:
    """Returns (ajwt_compact, jti)."""
    r = post_json("/agent/token", {"agent_id": agent_id, "ttl_secs": 600},
                  {"x-sauron-session": session})
    if not r.ok:
        raise RuntimeError(f"issue token failed: {r.text}")
    ajwt = r.json()["ajwt"]
    # decode jti claim from middle segment
    parts = ajwt.split(".")
    payload_b = parts[1] + "=" * (-len(parts[1]) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload_b.encode()))
    return ajwt, claims["jti"]


def step_pop_challenge(session: str, agent_id: str) -> tuple[str, str]:
    r = post_json("/agent/pop/challenge", {"agent_id": agent_id},
                  {"x-sauron-session": session})
    if not r.ok:
        raise RuntimeError(f"pop challenge failed: {r.text}")
    j = r.json()
    return j["pop_challenge_id"], j["challenge"]


def step_action_challenge(
    pop_sk: Ed25519PrivateKey, agent_id: str, config_digest: str,
    human_ki: str, payment_ref: str, merchant_id: str, amount_minor: int,
    currency: str, ajwt_jti: str,
) -> dict:
    """Returns the canonical envelope JSON (with ring keys + signer index)."""
    body = {
        "agent_id": agent_id,
        "human_key_image": human_ki,
        "action": "payment_initiation",
        "resource": payment_ref,
        "merchant_id": merchant_id,
        "amount_minor": amount_minor,
        "currency": currency,
        "ajwt_jti": ajwt_jti,
        "ttl_secs": 120,
    }
    body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
    sig_headers = sign_call_headers(
        pop_sk, agent_id, config_digest,
        "POST", "/agent/action/challenge", body_bytes,
    )
    headers = {"content-type": "application/json", **sig_headers}
    r = requests.post(f"{CORE_URL}/agent/action/challenge",
                      headers=headers, data=body_bytes, timeout=15)
    if not r.ok:
        raise RuntimeError(f"action/challenge failed: HTTP {r.status_code} {r.text}")
    return r.json()


def step_payment_authorize(
    pop_sk: Ed25519PrivateKey, agent_id: str, config_digest: str,
    ajwt: str, amount_minor: int, currency: str,
    payment_ref: str, merchant_id: str,
    pop_challenge_id: str, pop_jws: str,
    ring_proof: dict[str, Any],
) -> dict:
    body = {
        "ajwt": ajwt,
        "amount_minor": amount_minor,
        "currency": currency,
        "payment_ref": payment_ref,
        "merchant_id": merchant_id,
        "pop_challenge_id": pop_challenge_id,
        "pop_jws": pop_jws,
        "agent_action": ring_proof,
    }
    body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
    sig_headers = sign_call_headers(
        pop_sk, agent_id, config_digest,
        "POST", "/agent/payment/authorize", body_bytes,
    )
    headers = {"content-type": "application/json", **sig_headers}
    r = requests.post(f"{CORE_URL}/agent/payment/authorize",
                      headers=headers, data=body_bytes, timeout=15)
    if not r.ok:
        raise RuntimeError(f"payment_authorize failed: HTTP {r.status_code} {r.text}")
    return r.json()


# ─── Main orchestration ─────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-actions", type=int, default=2,
                    help="how many real action receipts to generate (default 2)")
    ap.add_argument("--email", default="alice@sauron.dev")
    ap.add_argument("--password", default="pass_alice")
    args = ap.parse_args()

    # liveness
    r = requests.get(f"{CORE_URL}/health", timeout=3)
    if r.status_code != 200 or not r.json().get("ok"):
        print(f"core not healthy at {CORE_URL}", file=sys.stderr)
        return 2

    print("== before ==")
    before = admin_get("/admin/anchor/status")
    actions_before = admin_get("/admin/agent_actions/recent")
    print(f"  receipts={len(actions_before)} batches={before['agent_action_batches']} "
          f"btc_total={before['bitcoin_total']} sol_total={before['solana_total']}")

    # 1. Auth
    print("\n== 1. user_auth ==")
    session, human_ki = step_user_auth(args.email, args.password)
    print(f"  session ok, key_image={human_ki[:24]}…")

    # 2. Generate ring + PoP keys
    print("\n== 2. keygen (ring + PoP) ==")
    ring = keygen_ring()
    pop_sk = Ed25519PrivateKey.generate()
    pop_pub_raw = pop_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pop_pub_b64u = b64u(pop_pub_raw)
    pop_jkt = b64u(hashlib.sha256(pop_pub_raw).digest())
    print(f"  ring_pub={ring['public_key_hex'][:18]}… pop_jkt={pop_jkt[:14]}…")

    # 3. Register agent (paid scope: payment_initiation, EUR cap 100, allowlist)
    print("\n== 3. register agent ==")
    agent_id, config_digest, intent_json = step_register_agent(
        session, human_ki,
        ring["public_key_hex"], ring["ring_key_image_hex"],
        pop_pub_b64u, pop_jkt,
    )
    print(f"  agent_id={agent_id}")
    print(f"  config_digest={config_digest[:24]}…")

    # 4..N: produce action receipts
    successes = 0
    for i in range(args.n_actions):
        amount_minor = 1500 + (i * 250)   # 15.00, 17.50, … each ≤ maxAmount=100.00
        merchant_id = "mch_demo_payments"
        payment_ref = f"pay_demo_{int(time.time() * 1000)}_{i}"

        print(f"\n== 4.{i + 1} action receipt for {amount_minor / 100:.2f} EUR ==")

        # 4a. fresh A-JWT (each receipt consumes the jti)
        ajwt, jti = step_issue_ajwt(session, agent_id)

        # 4b. fresh PoP challenge → JWS (single-use)
        pch_id, challenge = step_pop_challenge(session, agent_id)
        pop_jws = make_pop_jws(pop_sk, challenge)

        # 4c. action challenge → canonical envelope
        ch = step_action_challenge(
            pop_sk, agent_id, config_digest,
            human_ki, payment_ref, merchant_id, amount_minor,
            "EUR", jti,
        )

        # 4d. ring-sign canonical
        ring_proof = sign_ring_challenge(ring["secret_hex"], json.dumps(ch))

        # 4e. payment_authorize (creates receipt)
        try:
            res = step_payment_authorize(
                pop_sk, agent_id, config_digest, ajwt,
                amount_minor, "EUR", payment_ref, merchant_id,
                pch_id, pop_jws, ring_proof,
            )
        except Exception as e:
            print(f"  FAILED: {e}")
            continue
        rcpt = res.get("action_receipt", {})
        successes += 1
        print(f"  receipt_id={rcpt.get('receipt_id')}")
        print(f"  action_hash={rcpt.get('action_hash', '')[:24]}…")
        print(f"  status={rcpt.get('status')}")

    print(f"\n== {successes}/{args.n_actions} action receipts created ==")

    # 5. Force anchor batch (BTC + Solana if SAURON_SOLANA_ENABLED=1)
    print("\n== 5. trigger anchor batch ==")
    run = admin_post("/admin/anchor/agent-actions/run")
    print(f"  result: {run}")

    # 6. After-state
    print("\n== after ==")
    time.sleep(1)
    after = admin_get("/admin/anchor/status")
    actions_after = admin_get("/admin/agent_actions/recent")
    print(f"  receipts={len(actions_after)} batches={after['agent_action_batches']} "
          f"btc_total={after['bitcoin_total']} sol_total={after['solana_total']}")
    print(f"  delta: receipts +{len(actions_after) - len(actions_before)}, "
          f"batches +{after['agent_action_batches'] - before['agent_action_batches']}, "
          f"BTC +{after['bitcoin_total'] - before['bitcoin_total']}, "
          f"SOL +{after['solana_total'] - before['solana_total']}")
    return 0 if successes > 0 else 1


if __name__ == "__main__":
    sys.exit(main())

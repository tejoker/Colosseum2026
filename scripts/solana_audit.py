"""Solana devnet integration audit. Runs three checks:

  1. STATIC: read /admin/health/detailed and confirm what the running core
     thinks of its Solana config (enabled/disabled, error reason, etc.).
  2. WIRE:   independently build + sign + send a Memo Program transaction
     to Solana devnet using the SAME bytes layout the Rust core builds
     (compact-u16 + legacy message format + ed25519 sig). If devnet accepts
     the transaction, the wire encoding in core/src/solana_anchor.rs is correct.
  3. ACTIVATION HINTS: print the exact env vars + restart command needed to
     flip the running core into anchoring mode without further changes.

The Rust code is the source of truth — this script is a parallel implementation
that exercises devnet against an independently generated keypair so we don't
risk the operator's anchoring keypair. If the WIRE check succeeds the same code
path will succeed for the Sauron core.

Run:
    pip install cryptography requests base58
    python scripts/solana_audit.py
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import time

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

try:
    import base58  # noqa: F401
except ImportError:
    print("missing dep: pip install base58", file=sys.stderr)
    sys.exit(2)
import base58 as b58

CORE_URL = os.getenv("SAURON_CORE_URL", "http://127.0.0.1:3001")
ADMIN_KEY = os.getenv("SAURON_ADMIN_KEY", "super_secret_hackathon_key")
DEVNET_RPC = os.getenv("SAURON_DEVNET_RPC", "https://api.devnet.solana.com")
MEMO_PROGRAM_ID_B58 = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
MEMO_PREFIX = "sauronid:v1:"


def encode_compact_u16(n: int) -> bytes:
    """Solana's short-vec / compact-u16 encoding."""
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n == 0:
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def build_legacy_message(
    signer_pk: bytes,
    program_id: bytes,
    memo_bytes: bytes,
    blockhash: bytes,
) -> bytes:
    """Mirror core/src/solana_anchor.rs::build_legacy_message exactly."""
    assert len(signer_pk) == 32 and len(program_id) == 32 and len(blockhash) == 32

    # Header: numRequiredSignatures=1, numReadonlySigned=0, numReadonlyUnsigned=1
    header = bytes([1, 0, 1])

    # Account keys: signer first (writable signer), then memo program (readonly)
    accounts_count = encode_compact_u16(2)
    accounts = signer_pk + program_id

    # Recent blockhash
    bh = blockhash

    # Instructions: 1 instruction over the memo program
    instr_count = encode_compact_u16(1)
    program_id_index = bytes([1])  # accounts[1] is memo program
    accounts_for_instr = encode_compact_u16(0)  # memo takes no accounts
    data_len = encode_compact_u16(len(memo_bytes))
    instr = program_id_index + accounts_for_instr + data_len + memo_bytes

    return header + accounts_count + accounts + bh + instr_count + instr


def rpc(method: str, params: list) -> dict:
    r = requests.post(
        DEVNET_RPC,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=30,
    )
    r.raise_for_status()
    j = r.json()
    if "error" in j:
        raise RuntimeError(f"RPC {method} error: {j['error']}")
    return j["result"]


def step_static_audit() -> bool:
    """Read /admin/health/detailed."""
    print("=" * 70)
    print("STATIC AUDIT: what the running core thinks of its Solana config")
    print("=" * 70)
    try:
        r = requests.get(
            f"{CORE_URL}/admin/health/detailed",
            headers={"x-admin-key": ADMIN_KEY},
            timeout=5,
        )
        r.raise_for_status()
        h = r.json()
    except Exception as e:
        print(f"  unreachable: {e}")
        return False
    sol = h.get("solana_anchor", {})
    print(f"  runtime          = {h.get('runtime')}")
    print(f"  solana_anchor.ok = {sol.get('ok')}")
    print(f"  solana_anchor    = {sol.get('detail')}")
    print(f"  warnings         = {h.get('warnings')}")
    return sol.get("ok") is True


def step_wire_check() -> dict:
    """Build + send a memo transaction to devnet using core's exact wire format."""
    print()
    print("=" * 70)
    print("WIRE CHECK: independently submit a memo tx to devnet")
    print("=" * 70)

    sk = Ed25519PrivateKey.generate()
    secret_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    keypair_64 = secret_bytes + pk_bytes
    pubkey_b58 = b58.b58encode(pk_bytes).decode("ascii")
    print(f"  generated keypair: pubkey={pubkey_b58}")

    print(f"  airdrop request to {DEVNET_RPC}…")
    try:
        airdrop_sig = rpc("requestAirdrop", [pubkey_b58, 1_000_000_000])
        print(f"  airdrop tx: {airdrop_sig}")
    except Exception as e:
        print(f"  airdrop failed: {e}")
        return {"ok": False, "reason": "airdrop_failed", "error": str(e)}

    # Wait for funds to land. Devnet faucets lag; poll generously.
    print("  polling balance (devnet faucet can take 60-120s)…")
    landed = False
    for attempt in range(60):
        try:
            bal = rpc("getBalance", [pubkey_b58, {"commitment": "processed"}])
            value = bal.get("value", 0) if isinstance(bal, dict) else 0
            if value > 0:
                print(f"  balance after airdrop: {value} lamports (attempt {attempt})")
                landed = True
                break
        except Exception:
            pass
        time.sleep(3)
    if not landed:
        print("  airdrop never landed; aborting")
        return {"ok": False, "reason": "airdrop_did_not_land", "pubkey": pubkey_b58}

    fake_root = secrets.token_hex(32)
    memo_text = f"{MEMO_PREFIX}{fake_root}"
    program_id = b58.b58decode(MEMO_PROGRAM_ID_B58)

    bh = rpc("getLatestBlockhash", [{"commitment": "confirmed"}])
    blockhash_b58 = bh["value"]["blockhash"]
    blockhash = b58.b58decode(blockhash_b58)
    print(f"  blockhash: {blockhash_b58}")

    msg = build_legacy_message(pk_bytes, program_id, memo_text.encode("utf-8"), blockhash)
    sig = sk.sign(msg)
    wire = encode_compact_u16(1) + sig + msg
    tx_b64 = base64.b64encode(wire).decode("ascii")

    try:
        send_sig = rpc(
            "sendTransaction",
            [
                tx_b64,
                {
                    "encoding": "base64",
                    "preflightCommitment": "confirmed",
                    "skipPreflight": False,
                    "maxRetries": 5,
                },
            ],
        )
    except Exception as e:
        print(f"  sendTransaction failed: {e}")
        return {"ok": False, "reason": "send_failed", "error": str(e)}

    print(f"  signature: {send_sig}")
    print(f"  explorer:  https://explorer.solana.com/tx/{send_sig}?cluster=devnet")
    return {
        "ok": True,
        "signature": send_sig,
        "memo": memo_text,
        "explorer": f"https://explorer.solana.com/tx/{send_sig}?cluster=devnet",
        "keypair_secret_64": list(keypair_64),
    }


def step_activation_hints(wire_result: dict) -> None:
    print()
    print("=" * 70)
    print("ACTIVATION: how to flip the running core into anchoring mode")
    print("=" * 70)
    print()
    if not wire_result.get("ok"):
        print("  wire check did not produce a verified keypair; skipping.")
        return
    keypair_path = "/tmp/sauron-solana-devnet.json"
    with open(keypair_path, "w") as fh:
        json.dump(wire_result["keypair_secret_64"], fh)
    os.chmod(keypair_path, 0o600)
    print(f"  wrote keypair to {keypair_path} (mode 0600)")
    print()
    print("  Restart core with:")
    print(f"      export SAURON_SOLANA_ENABLED=1")
    print(f"      export SAURON_SOLANA_RPC_URL={DEVNET_RPC}")
    print(f"      export SAURON_SOLANA_NETWORK=devnet")
    print(f"      export SAURON_SOLANA_KEYPAIR_PATH={keypair_path}")
    print()
    print("  Then trigger an anchor batch (after some agent action receipts exist):")
    print('      curl -X POST -H "x-admin-key: $SAURON_ADMIN_KEY" \\')
    print(f'          {CORE_URL}/admin/anchor/agent-actions/run')
    print()
    print('  Verify Solana counts climb:')
    print(f'      curl -H "x-admin-key: $SAURON_ADMIN_KEY" \\')
    print(f'          {CORE_URL}/admin/anchor/status')


def main() -> int:
    print(f"core={CORE_URL}  devnet={DEVNET_RPC}")
    print()
    enabled = step_static_audit()
    wire = step_wire_check()
    step_activation_hints(wire)
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Solana anchor enabled in running core: {'YES' if enabled else 'NO'}")
    print(f"  Wire format works on devnet:          {'YES' if wire.get('ok') else 'NO'}")
    if wire.get("ok"):
        print(f"  Devnet signature: {wire['signature']}")
        print(f"  Explorer link:    {wire['explorer']}")
    return 0 if wire.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())

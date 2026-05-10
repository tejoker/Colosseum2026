"""Generate a fresh Solana devnet keypair and fund it via airdrop.

Tries `requestAirdrop` against multiple public RPCs with backoff, since the
default api.devnet.solana.com is heavily rate-limited. Writes the keypair
to /tmp/sauron-solana-devnet.json (Solana convention: 64-byte JSON array =
[secret(32) || public(32)]).

After this script reports a positive balance, restart the core with:

    export SAURON_SOLANA_ENABLED=1
    export SAURON_SOLANA_RPC_URL=https://api.devnet.solana.com
    export SAURON_SOLANA_NETWORK=devnet
    export SAURON_SOLANA_KEYPAIR_PATH=/tmp/sauron-solana-devnet.json

Then trigger an anchor batch and check /admin/anchor/status.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

try:
    import base58 as b58
except ImportError:
    print("missing dep: pip install base58", file=sys.stderr)
    sys.exit(2)

DEVNET_RPCS = [
    "https://api.devnet.solana.com",
    "https://devnet.helius-rpc.com",  # may be rate-limited without API key
    "https://rpc.ankr.com/solana_devnet",
]


def rpc_call(url: str, method: str, params: list, timeout: int = 15) -> dict:
    r = requests.post(
        url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=timeout,
    )
    if r.status_code == 429:
        raise RuntimeError("rate-limited (HTTP 429)")
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
    j = r.json()
    if "error" in j:
        raise RuntimeError(f"RPC error: {j['error']}")
    return j["result"]


def try_airdrop(pubkey: str) -> str | None:
    """Try each RPC in turn. Returns the airdrop signature if any worked."""
    for url in DEVNET_RPCS:
        for attempt in range(3):
            try:
                sig = rpc_call(url, "requestAirdrop", [pubkey, 1_000_000_000])
                print(f"  airdrop accepted by {url}: {sig}")
                return sig
            except Exception as e:
                msg = str(e)[:120]
                print(f"  {url} attempt {attempt + 1}: {msg}")
                if "429" in msg or "rate" in msg.lower():
                    time.sleep(8 * (attempt + 1))
                else:
                    break
    return None


def wait_for_balance(pubkey: str, rpc: str, max_sec: int = 180) -> int:
    deadline = time.time() + max_sec
    while time.time() < deadline:
        try:
            bal = rpc_call(rpc, "getBalance", [pubkey, {"commitment": "confirmed"}])
            value = bal.get("value", 0) if isinstance(bal, dict) else 0
            if value > 0:
                return value
        except Exception:
            pass
        time.sleep(3)
    return 0


def write_keypair(secret_bytes: bytes, public_bytes: bytes, path: str) -> None:
    payload = list(secret_bytes + public_bytes)
    if len(payload) != 64:
        raise SystemExit(f"refusing to write keypair with length {len(payload)}")
    with open(path, "w") as fh:
        json.dump(payload, fh)
    os.chmod(path, 0o600)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/sauron-solana-devnet.json")
    ap.add_argument(
        "--rpc",
        default="https://api.devnet.solana.com",
        help="primary RPC for balance polling once airdrop lands",
    )
    args = ap.parse_args()

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
    pubkey_b58 = b58.b58encode(pk_bytes).decode("ascii")

    write_keypair(secret_bytes, pk_bytes, args.out)
    print(f"keypair written:  {args.out}")
    print(f"pubkey:           {pubkey_b58}")

    # Try airdrop
    sig = try_airdrop(pubkey_b58)
    if not sig:
        print()
        print("===========================================================")
        print("All public devnet faucets are rate-limited right now.")
        print("Manually airdrop via the web faucet, then re-run this script:")
        print(f"  https://faucet.solana.com/?wallet={pubkey_b58}&cluster=devnet")
        print("Or, if you have the Solana CLI installed:")
        print(f"  solana airdrop 2 {pubkey_b58} --url {args.rpc}")
        print("===========================================================")
        return 1

    # Wait for it to confirm
    print(f"  polling balance on {args.rpc}…")
    bal = wait_for_balance(pubkey_b58, args.rpc, max_sec=180)
    if bal == 0:
        print("  balance still 0 after 180s. Airdrop may still arrive — retry shortly.")
        return 1
    print(f"  balance confirmed: {bal} lamports")

    print()
    print("===========================================================")
    print("READY. Restart core with these env vars:")
    print()
    print(f"  export SAURON_SOLANA_ENABLED=1")
    print(f"  export SAURON_SOLANA_RPC_URL={args.rpc}")
    print(f"  export SAURON_SOLANA_NETWORK=devnet")
    print(f"  export SAURON_SOLANA_KEYPAIR_PATH={args.out}")
    print()
    print(f"Pubkey on Explorer:")
    print(f"  https://explorer.solana.com/address/{pubkey_b58}?cluster=devnet")
    print("===========================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())

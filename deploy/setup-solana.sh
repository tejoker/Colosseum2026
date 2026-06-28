#!/usr/bin/env bash
# Generate + fund a Solana devnet keypair for anchoring, written to
# deploy/secrets/solana-devnet.json (mounted into the backend container).
#
# Devnet airdrops are rate-limited; the underlying script retries across
# several public RPCs. Re-run if the airdrop times out.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/secrets/solana-devnet.json"
mkdir -p "$here/secrets"

python3 "$here/../scripts/solana_devnet_setup.py" --out "$out"

echo
echo "keypair at: $out"
echo "It is mounted read-only into the backend at /etc/sauronid/solana-keypair.json."
echo "If the airdrop did not land, re-run this script (devnet faucets are flaky)."

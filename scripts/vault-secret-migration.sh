#!/usr/bin/env bash
# vault-secret-migration.sh
#
# One-shot helper that takes the four SauronID root secrets currently held in
# plaintext env vars and wraps each via Vault Transit. The operator copies the
# `*_WRAPPED` lines into their secrets manager (k8s Secret, Doppler, 1Password
# Secrets Automation, AWS Secrets Manager, …) and then deletes the plaintext
# values from wherever they live today.
#
# After migration the server is started with:
#   SAURON_VAULT_TRANSIT_ENABLED=1
#   SAURON_VAULT_ADDR=https://vault.example.com:8200
#   SAURON_VAULT_TOKEN=<service-token>
#   SAURON_VAULT_TRANSIT_KEY=sauronid-root
#   SAURON_TOKEN_SECRET_WRAPPED=vault:v1:…
#   SAURON_JWT_SECRET_WRAPPED=vault:v1:…
#   SAURON_OPRF_SEED_WRAPPED=vault:v1:…
#   SAURON_ADMIN_KEY_WRAPPED=vault:v1:…
# and the plaintext SAURON_*_SECRET env vars are NEVER set.
#
# Requires:
#   - `vault` CLI on PATH
#   - `VAULT_ADDR` + `VAULT_TOKEN` exported and a working session
#     (`vault status` returns OK and `vault token lookup` succeeds)
#   - The transit engine mounted and a key created:
#       vault secrets enable transit
#       vault write -f transit/keys/sauronid-root
#
# Usage:
#   SAURON_TOKEN_SECRET=...    \
#   SAURON_JWT_SECRET=...      \
#   SAURON_OPRF_SEED=...       \
#   SAURON_ADMIN_KEY=...       \
#   ./scripts/vault-secret-migration.sh
#
# Optional:
#   SAURON_VAULT_TRANSIT_KEY (defaults to `sauronid-root`)
#   --help / -h prints this banner and exits 0

set -euo pipefail

usage() {
    sed -n '2,40p' "$0"
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

# ── sanity checks ────────────────────────────────────────────────────────────

if ! command -v vault >/dev/null 2>&1; then
    echo "[FATAL] 'vault' CLI not found on PATH" >&2
    echo "        Install: https://developer.hashicorp.com/vault/install" >&2
    exit 2
fi

if [[ -z "${VAULT_ADDR:-}" ]]; then
    echo "[FATAL] VAULT_ADDR is not set" >&2
    exit 2
fi
if [[ -z "${VAULT_TOKEN:-}" ]]; then
    echo "[FATAL] VAULT_TOKEN is not set" >&2
    exit 2
fi

if ! vault status >/dev/null 2>&1; then
    echo "[FATAL] 'vault status' failed — is the cluster reachable / unsealed?" >&2
    exit 2
fi

TRANSIT_KEY="${SAURON_VAULT_TRANSIT_KEY:-sauronid-root}"

# Confirm the key exists. `vault read transit/keys/<name>` returns 2 on absent.
if ! vault read "transit/keys/${TRANSIT_KEY}" >/dev/null 2>&1; then
    echo "[FATAL] transit key '${TRANSIT_KEY}' not found." >&2
    echo "        Create with:" >&2
    echo "          vault secrets enable transit" >&2
    echo "          vault write -f transit/keys/${TRANSIT_KEY}" >&2
    exit 2
fi

# ── wrap each secret ─────────────────────────────────────────────────────────

SECRETS=(
    SAURON_TOKEN_SECRET
    SAURON_JWT_SECRET
    SAURON_OPRF_SEED
    SAURON_ADMIN_KEY
)

missing=()
for name in "${SECRETS[@]}"; do
    if [[ -z "${!name:-}" ]]; then
        missing+=("$name")
    fi
done
if (( ${#missing[@]} > 0 )); then
    echo "[FATAL] missing plaintext env vars: ${missing[*]}" >&2
    echo "        Export each before invoking this script." >&2
    exit 2
fi

echo "# === SauronID Vault Transit wrapping output ==="
echo "# Generated on $(date -u +%Y-%m-%dT%H:%M:%SZ) against ${VAULT_ADDR}"
echo "# Transit key: ${TRANSIT_KEY}"
echo "# Copy these lines into your secrets manager. Then delete the plaintext"
echo "# SAURON_*_SECRET values from wherever they live today."
echo "#"

for name in "${SECRETS[@]}"; do
    pt_b64=$(printf '%s' "${!name}" | base64 | tr -d '\n')
    ct=$(vault write -field=ciphertext "transit/encrypt/${TRANSIT_KEY}" "plaintext=${pt_b64}")
    if [[ -z "$ct" || "${ct:0:7}" != "vault:v" ]]; then
        echo "[FATAL] unexpected ciphertext for ${name}: ${ct:0:32}…" >&2
        exit 3
    fi
    echo "${name}_WRAPPED=${ct}"
done

echo "#"
echo "# Runtime env to set in addition to the wrapped values:"
echo "#   SAURON_VAULT_TRANSIT_ENABLED=1"
echo "#   SAURON_VAULT_ADDR=${VAULT_ADDR}"
echo "#   SAURON_VAULT_TOKEN=<service token with transit/decrypt/${TRANSIT_KEY} capability>"
echo "#   SAURON_VAULT_TRANSIT_KEY=${TRANSIT_KEY}"

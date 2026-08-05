#!/usr/bin/env bash
set -euo pipefail

db=${1:-}
cargo_bin=${SAURON_CARGO:-cargo}
[[ -n "$db" ]] || { echo "usage: $0 <restored.sqlite>" >&2; exit 2; }
[[ -f "$db" ]] || { echo "restored database not found: $db" >&2; exit 1; }
[[ -n "${SAURON_AUDIT_HMAC_KEY:-}" || -n "${SAURON_AUDIT_HMAC_KEY_FILE:-}" ]] || {
  echo "SAURON_AUDIT_HMAC_KEY or SAURON_AUDIT_HMAC_KEY_FILE is required" >&2
  exit 1
}

if [[ -n "${SAURON_AUDIT_HMAC_KEY_FILE:-}" ]]; then
  [[ -f "$SAURON_AUDIT_HMAC_KEY_FILE" ]] || { echo "audit key file not found" >&2; exit 1; }
  export SAURON_AUDIT_HMAC_KEY="$(<"$SAURON_AUDIT_HMAC_KEY_FILE")"
fi

"$cargo_bin" run --quiet --locked --manifest-path core/Cargo.toml --bin sauronid-cli -- \
  verify-audit --database "$db"

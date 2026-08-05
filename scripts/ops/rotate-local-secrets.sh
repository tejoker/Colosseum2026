#!/usr/bin/env bash
set -euo pipefail

destination=${1:-prod.secrets.env}
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 2; }
if [[ -L "$destination" ]]; then
  echo "refusing to replace symlink: $destination" >&2
  exit 1
fi

parent=$(dirname "$destination")
mkdir -p "$parent"
tmp=$(mktemp "$parent/.sauron-secrets.XXXXXX")
trap 'rm -f "$tmp"' EXIT
umask 077

{
  echo '# Generated locally; never commit or transmit this file.'
  echo "# Rotated at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for name in \
    SAURON_ADMIN_KEY \
    SAURON_ADMIN_JWT_HS256_SECRET \
    SAURON_TOKEN_SECRET \
    SAURON_JWT_SECRET \
    SAURON_AUDIT_HMAC_KEY \
    SAURON_DASHBOARD_SESSION_SECRET \
    SAURON_ISSUER_SHARED_SECRET
  do
    printf '%s=%s\n' "$name" "$(openssl rand -hex 32)"
  done
} >"$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$destination"
trap - EXIT

echo "rotated local secret set at $destination (values not printed)"
echo "Deploy through the target secret manager, revoke prior values, and invalidate outstanding sessions before recording production rotation complete."

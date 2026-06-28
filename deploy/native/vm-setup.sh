#!/usr/bin/env bash
# No-Docker VM setup. Run ON the cloud VM, from the dir democtl rsynced to
# (e.g. ~/sauronid-demo/native), after creating core.env + site.env here:
#     sudo bash vm-setup.sh
#
# Installs Caddy (+ Node 20 if the dashboard is enabled), lays out
# /opt/sauronid, installs systemd units, and starts everything. Idempotent.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX=/opt/sauronid

[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo bash vm-setup.sh" >&2; exit 1; }
[[ -f "$HERE/core.env" ]] || { echo "FATAL: create $HERE/core.env (cp core.env.example core.env)" >&2; exit 1; }
[[ -f "$HERE/site.env" ]] || { echo "FATAL: create $HERE/site.env (cp site.env.example site.env)" >&2; exit 1; }
[[ -x "$HERE/dist/sauron-core" ]] || { echo "FATAL: $HERE/dist/sauron-core missing — run 'democtl build-native' then 'deploy-native'" >&2; exit 1; }

# Read only the keys we need WITHOUT sourcing — site.env holds the bcrypt hash
# (DASH_BASICAUTH_HASH=$2a$...) which bash would try to expand as positional
# params under `set -u`. Caddy reads site.env literally via its EnvironmentFile.
site_get() { grep -E "^$1=" "$HERE/site.env" | head -1 | cut -d= -f2- | tr -d '\r'; }
ENABLE_DASHBOARD="$(site_get ENABLE_DASHBOARD)"; ENABLE_DASHBOARD="${ENABLE_DASHBOARD:-0}"
CORE_DOMAIN="$(site_get CORE_DOMAIN)"
DASH_DOMAIN="$(site_get DASH_DOMAIN)"
DASH_USER="$(site_get DASH_USER)"

echo "==> service user + layout"
id -u sauronid >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin sauronid
mkdir -p "$PREFIX/data"
install -m 0755 "$HERE/dist/sauron-core" "$PREFIX/sauron-core"
[[ -f "$HERE/dist/seed.sh" ]] && install -m 0755 "$HERE/dist/seed.sh" "$PREFIX/seed.sh" || true
install -m 0600 "$HERE/core.env" "$PREFIX/core.env"
install -m 0644 "$HERE/site.env" "$PREFIX/site.env"
[[ -f "$HERE/dist/solana-devnet.json" ]] && install -m 0600 "$HERE/dist/solana-devnet.json" "$PREFIX/solana-keypair.json" || true

echo "==> ca-certificates"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg >/dev/null

echo "==> Caddy"
if ! command -v caddy >/dev/null 2>&1; then
  apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https >/dev/null
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq
  apt-get install -y -qq caddy >/dev/null
fi
# Feed site.env (domains, basic-auth hash) to Caddy's process env so its
# {$VAR} placeholders resolve — including the bcrypt hash, untouched.
mkdir -p /etc/systemd/system/caddy.service.d
cat > /etc/systemd/system/caddy.service.d/sauronid.conf <<EOF
[Service]
EnvironmentFile=$PREFIX/site.env
EOF

echo "==> core service"
install -m 0644 "$HERE/sauronid-core.service" /etc/systemd/system/sauronid-core.service

if [[ "$ENABLE_DASHBOARD" == "1" ]]; then
  echo "==> dashboard (Node 20 + service)"
  if ! command -v node >/dev/null 2>&1 || [[ "$(node -v 2>/dev/null | sed 's/v\([0-9]*\).*/\1/')" -lt 20 ]]; then
    # Official Node static tarball — works on any glibc x64 Linux regardless of
    # distro codename (nodesource apt repos lag brand-new Ubuntu releases).
    apt-get install -y -qq xz-utils >/dev/null
    NODE_VER=v20.18.1
    curl -fsSL "https://nodejs.org/dist/${NODE_VER}/node-${NODE_VER}-linux-x64.tar.xz" -o /tmp/node.tar.xz
    rm -rf /opt/node && mkdir -p /opt/node
    tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1
    ln -sf /opt/node/bin/node /usr/bin/node
    ln -sf /opt/node/bin/npm /usr/bin/npm
  fi
  rm -rf "$PREFIX/dashboard"
  cp -r "$HERE/dist/dashboard" "$PREFIX/dashboard"
  # Dedicated dashboard env (admin key + tenants only) — avoids inheriting the
  # core's PORT=3001 which would collide. Extracted from core.env (no sourcing).
  DASH_ADMIN="$(grep -E '^SAURON_ADMIN_KEY=' "$HERE/core.env" | head -1 | cut -d= -f2-)"
  DASH_TENANTS="$(grep -E '^SAURONID_TENANTS=' "$HERE/core.env" | head -1 | cut -d= -f2-)"
  cat > "$PREFIX/dashboard.env" <<EOF
SAURON_ADMIN_KEY=$DASH_ADMIN
SAURONID_TENANTS=${DASH_TENANTS:-default}
EOF
  chmod 600 "$PREFIX/dashboard.env"
  install -m 0644 "$HERE/sauronid-dashboard.service" /etc/systemd/system/sauronid-dashboard.service
  install -m 0644 "$HERE/Caddyfile.full" /etc/caddy/Caddyfile
else
  rm -f /etc/systemd/system/sauronid-dashboard.service
  install -m 0644 "$HERE/Caddyfile.core" /etc/caddy/Caddyfile
fi

chown -R sauronid:sauronid "$PREFIX"

echo "==> start"
systemctl daemon-reload
# Use restart (not just enable --now) so a redeploy actually picks up the new
# binary / dashboard bundle — enable --now is a no-op on an already-running unit.
systemctl enable sauronid-core.service >/dev/null 2>&1 || true
systemctl restart sauronid-core.service
if [[ "$ENABLE_DASHBOARD" == "1" ]]; then
  systemctl enable sauronid-dashboard.service >/dev/null 2>&1 || true
  systemctl restart sauronid-dashboard.service
else
  systemctl disable --now sauronid-dashboard.service >/dev/null 2>&1 || true
fi
systemctl restart caddy

echo
echo "==> done. status:"
systemctl --no-pager --lines=0 status sauronid-core.service | head -3 || true
echo "core   : https://${CORE_DOMAIN}/health"
[[ "$ENABLE_DASHBOARD" == "1" ]] && echo "dash   : https://${DASH_DOMAIN}  (basic-auth: ${DASH_USER})"
echo "logs   : journalctl -u sauronid-core -f"

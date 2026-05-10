#!/usr/bin/env bash
# start-test.sh — démarrage rapide sans build (mode dev)
# Utilise le binaire Rust déjà compilé + npm run dev pour les frontends

set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"

# ── Couleurs ─────────────────────────────────────────────────────────────────
GRN='\033[0;32m'; YLW='\033[1;33m'; RED='\033[0;31m'; RST='\033[0m'
log()  { echo -e "${GRN}[start-test]${RST} $*"; }
warn() { echo -e "${YLW}[warn]${RST} $*"; }

# ── Cleanup ──────────────────────────────────────────────────────────────────
PIDS=()
cleanup() {
  echo ""
  log "Arrêt de tous les processus..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  log "Arrêté."
}
trap cleanup INT TERM

# ── 1. Backend Rust ──────────────────────────────────────────────────────────
log "[1/6] Backend Rust → :3001"
cd "$ROOT/core"

BINARY="./target/release/sauron-core"
if [ ! -f "$BINARY" ]; then
  warn "Binaire release introuvable, utilisation de debug..."
  BINARY="./target/debug/sauron-core"
fi
if [ ! -f "$BINARY" ]; then
  warn "Aucun binaire trouvé — lance 'cargo build' d'abord !"
  warn "Fallback: cargo run (lent au premier démarrage)"
  ENV="${ENV:-development}" \
  SAURON_ADMIN_KEY="${SAURON_ADMIN_KEY:-super_secret_hackathon_key}" \
  SAURON_ISSUER_URL="${SAURON_ISSUER_URL:-http://localhost:4000}" \
  SAURON_ISSUER_SHARED_SECRET="${SAURON_ISSUER_SHARED_SECRET:-sauron_issuer_shared_dev_key_change_me}" \
  cargo run --bin sauron-core &
else
  ENV="${ENV:-development}" \
  SAURON_ADMIN_KEY="${SAURON_ADMIN_KEY:-super_secret_hackathon_key}" \
  SAURON_ISSUER_URL="${SAURON_ISSUER_URL:-http://localhost:4000}" \
  SAURON_ISSUER_SHARED_SECRET="${SAURON_ISSUER_SHARED_SECRET:-sauron_issuer_shared_dev_key_change_me}" \
  "$BINARY" &
fi
CORE_PID=$!
PIDS+=("$CORE_PID")

# ── Attendre que le backend soit prêt ────────────────────────────────────────
log "Attente du backend..."
for i in $(seq 1 120); do
  if curl -sf http://localhost:3001/admin/stats \
       -H "x-admin-key: super_secret_hackathon_key" > /dev/null 2>&1; then
    log "Backend prêt ✓"
    break
  fi
  sleep 1
  if [ "$i" -eq 120 ]; then
    echo -e "${RED}[error]${RST} Backend non disponible après 120s."
    exit 1
  fi
done

# ── 2. Seed ──────────────────────────────────────────────────────────────────
log "[2/6] Seed (clients + users)..."
cd "$ROOT/core"
SAURON_URL=http://localhost:3001 bash seed.sh

# (Optional archived Python KYC: legacy/KYC — not started here.)

# ── 3. Analytics API (Python) ────────────────────────────────────────────────
log "[3/6] Analytics API → :8002"
cd "$ROOT/data/sauron"
if [ ! -d ".venv" ]; then
  warn "Création du venv sauron..."
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi
SAURON_URL=http://localhost:3001 \
DATA_DIR="$ROOT/data" \
  .venv/bin/uvicorn app:app --host 0.0.0.0 --port 8002 --reload &
SAURON_PID=$!
PIDS+=("$SAURON_PID")

# ── 4. Partner Portal (Next.js) ──────────────────────────────────────────────
log "[4/6] Partner Portal → :3000"
cd "$ROOT/partner-portal"
if [ ! -d "node_modules" ]; then
  warn "Installation des dépendances npm (partner-portal)..."
  npm install --silent
fi
NEXT_PUBLIC_API_URL=http://localhost:3001 \
SAURON_CORE_INTERNAL_URL=http://localhost:3001 \
NEXT_PUBLIC_ZKP_ISSUER_URL=http://localhost:4000 \
TRUSTAI_ALLOW_UNAUTHENTICATED_ADMIN_PROXY=1 \
DASHBOARD_INTERNAL_URL=http://localhost:8003 \
  npm run dev -- -p 3000 &
PORTAL_PID=$!
PIDS+=("$PORTAL_PID")

# ── 5. Sauron Dashboard UI (Next.js) ─────────────────────────────────────────
log "[5/6] Sauron Dashboard → :8003"
cd "$ROOT/sauron-dashboard"
if [ ! -d "node_modules" ]; then
  warn "Installation des dépendances npm (sauron-dashboard)..."
  npm install --silent
fi
NEXT_PUBLIC_API_URL=http://localhost:3001 \
NEXT_PUBLIC_DASH_API_URL=http://localhost:8002 \
SAURON_CORE_INTERNAL_URL=http://localhost:3001 \
TRUSTAI_ALLOW_UNAUTHENTICATED_ADMIN_PROXY=1 \
  npm run dev -- -p 8003 &
DASH_PID=$!
PIDS+=("$DASH_PID")

# ── 6. ZKP Issuer (OID4VCI + proof verification) ───────────────────────────
log "[6/6] ZKP Issuer → :4000"
cd "$ROOT/zkp/issuer"
if [ ! -d "node_modules" ]; then
  warn "Installation des dépendances npm (issuer)..."
  npm install --silent
fi
if [ ! -d "dist" ]; then
  warn "Build du service issuer..."
  npm run build
fi
ISSUER_SEED="${ISSUER_SEED:-sauronid-issuer-seed-hackathon}" \
SAURON_ISSUER_SHARED_SECRET="${SAURON_ISSUER_SHARED_SECRET:-sauron_issuer_shared_dev_key_change_me}" \
  npm run start &
ISSUER_PID=$!
PIDS+=("$ISSUER_PID")

# ── Résumé ───────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${GRN}Partner + Bank + Dashboard (proxy) →${RST} http://localhost:3000"
echo -e "  ${GRN}Rust Backend API                    →${RST} http://localhost:3001"
echo -e "  ${YLW}Internal services (proxied)         →${RST} 8002 / 8003"
echo ""
echo -e "  ${YLW}Ctrl+C pour tout arrêter${RST}"
echo ""

wait

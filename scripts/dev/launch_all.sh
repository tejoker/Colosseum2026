#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  ENV=development docker compose -f "$REPO_ROOT/deploy/docker-compose.yml" up --build -d
else
  echo "[launch_all] docker unavailable in this environment, switching to local stack via start.sh"
  bash "$SCRIPT_DIR/start.sh"
fi

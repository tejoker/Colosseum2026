#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
bad=0

while IFS= read -r occurrence; do
  action="${occurrence#*uses:}"
  action="${action%%#*}"
  action="$(printf '%s' "$action" | xargs)"
  ref="${action##*@}"
  if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
    printf 'mutable GitHub Action reference: %s\n' "$occurrence" >&2
    bad=1
  fi
done < <(grep -R -n -E 'uses:[[:space:]]*[^[:space:]#]+@[^[:space:]#]+' \
  "$ROOT/.github/workflows" --include='*.yml' --include='*.yaml' || true)

if [[ "$bad" -ne 0 ]]; then
  printf 'Every remote GitHub Action must be pinned to a full 40-character commit SHA.\n' >&2
  exit 1
fi

printf 'GitHub Action references are commit-pinned: OK\n'

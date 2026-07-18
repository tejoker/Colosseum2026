#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <live.sqlite> [verified-backup.sqlite]" >&2
  exit 2
fi

source_db=$1
destination=${2:-}
command -v sqlite3 >/dev/null || { echo "sqlite3 is required" >&2; exit 2; }
[[ -f "$source_db" ]] || { echo "database does not exist: $source_db" >&2; exit 2; }

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
snapshot="$workdir/snapshot.sqlite"

# SQLite's online backup API gives a transactionally consistent snapshot even
# while WAL writers are active. Never copy the database and WAL files manually.
sqlite3 "$source_db" ".timeout 30000" ".backup '$snapshot'"

integrity=$(sqlite3 "$snapshot" "PRAGMA integrity_check;")
[[ "$integrity" == "ok" ]] || { echo "integrity_check failed: $integrity" >&2; exit 1; }

foreign_keys=$(sqlite3 "$snapshot" "PRAGMA foreign_key_check;")
[[ -z "$foreign_keys" ]] || { echo "foreign_key_check failed:" >&2; echo "$foreign_keys" >&2; exit 1; }

for table in users agents policies agent_action_receipts agent_action_anchors security_audit_log; do
  exists=$(sqlite3 "$snapshot" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='$table';")
  [[ "$exists" == "1" ]] || { echo "critical table missing: $table" >&2; exit 1; }
  sqlite3 "$snapshot" "SELECT '$table=' || COUNT(*) FROM \"$table\";"
done

if [[ -n "$destination" ]]; then
  [[ ! -e "$destination" ]] || { echo "refusing to overwrite: $destination" >&2; exit 2; }
  cp --preserve=mode,timestamps "$snapshot" "$destination"
  chmod 0600 "$destination"
  echo "verified_backup=$destination"
else
  echo "verified_backup=temporary_only"
fi

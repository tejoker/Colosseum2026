#!/usr/bin/env python3
"""Create and validate a transactionally consistent SQLite restore artifact."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

CRITICAL_TABLES = (
    "users",
    "agents",
    "policies",
    "agent_action_receipts",
    "agent_action_anchors",
    "security_audit_log",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if not args.source.is_file():
        parser.error(f"source database does not exist: {args.source}")
    if args.destination.exists() or args.destination.is_symlink():
        parser.error(f"refusing to overwrite destination: {args.destination}")

    args.destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.destination, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(fd)
    counts: dict[str, int] = {}
    try:
        source = sqlite3.connect(f"file:{args.source}?mode=ro", uri=True, timeout=30)
        restored = sqlite3.connect(args.destination, timeout=30)
        with source, restored:
            source.backup(restored)
        source.close()

        integrity = restored.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError(f"integrity_check failed: {integrity}")
        foreign_keys = restored.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_keys:
            raise RuntimeError(f"foreign_key_check failed: {foreign_keys[:5]}")
        existing = {
            row[0]
            for row in restored.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        missing = sorted(set(CRITICAL_TABLES) - existing)
        if missing:
            raise RuntimeError(f"critical tables missing: {', '.join(missing)}")
        for table in CRITICAL_TABLES:
            counts[table] = restored.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        restored.close()
    except Exception:
        args.destination.unlink(missing_ok=True)
        raise

    print(json.dumps({"verified_backup": str(args.destination), "counts": counts}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"backup verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

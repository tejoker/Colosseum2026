#!/usr/bin/env python3
"""Clean-room backup/restore drill for the supported SQLite topology."""

import os
import sqlite3
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TABLES = (
    "users",
    "agents",
    "policies",
    "agent_action_receipts",
    "agent_action_anchors",
    "security_audit_log",
)

with tempfile.TemporaryDirectory() as tmp:
    source = Path(tmp) / "live.sqlite"
    backup = Path(tmp) / "backup.sqlite"
    db = sqlite3.connect(source)
    for table in TABLES:
        if table == "security_audit_log":
            db.execute(
                """CREATE TABLE security_audit_log (
                audit_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
                event_type TEXT NOT NULL, event_json TEXT NOT NULL,
                timestamp INTEGER NOT NULL, seq INTEGER,
                prev_hash TEXT NOT NULL DEFAULT '',
                entry_hash TEXT NOT NULL DEFAULT '')"""
            )
        else:
            db.execute(f'CREATE TABLE "{table}" (id TEXT PRIMARY KEY, value TEXT NOT NULL)')
    db.execute("INSERT INTO agent_action_receipts VALUES ('receipt-1', 'immutable-sentinel')")
    db.commit()
    db.close()

    subprocess.run(
        ["python3", str(ROOT / "scripts/ops/verify-sqlite-backup.py"), str(source), str(backup)],
        check=True,
    )

    # A later mutation of the live database must not alter the restore point.
    db = sqlite3.connect(source)
    db.execute("UPDATE agent_action_receipts SET value='mutated' WHERE id='receipt-1'")
    db.commit()
    db.close()

    restored = sqlite3.connect(f"file:{backup}?mode=ro", uri=True)
    value = restored.execute(
        "SELECT value FROM agent_action_receipts WHERE id='receipt-1'"
    ).fetchone()[0]
    assert value == "immutable-sentinel", value
    assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    restored.close()

    env = os.environ.copy()
    env["SAURON_AUDIT_HMAC_KEY"] = "backup-drill-only-key-not-for-production"
    subprocess.run(
        [str(ROOT / "scripts/ops/verify-restored-sqlite.sh"), str(backup)],
        cwd=ROOT,
        env=env,
        check=True,
    )

print("SQLite clean-room backup/restore drill: OK")

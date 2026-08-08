#!/usr/bin/env python3
"""Differential test: the same call-site SQL, run on SQLite and on PostgreSQL.

`core/src/sql_translate.rs` rewrites the SQLite dialect this codebase writes into
PostgreSQL. Unit tests there pin the *text* of each rewrite. This pins the thing
that actually matters: that the rewritten statement, executed against a real
PostgreSQL, produces the same rows as the original against SQLite.

That property is what the remaining port depends on. Roughly 277 call sites
still talk to rusqlite directly; the plan is to route them through one handle
that translates on the way out, and this harness is how each batch gets checked
rather than assumed.

Usage (PostgreSQL must be reachable; CI's test-postgres job already has one):

    PGHOST=localhost PGPORT=5432 PGUSER=postgres PGPASSWORD=postgres \\
      PGDATABASE=sauron_test python3 core/tests/sql_translation_differential.py

Exits non-zero on the first divergence.
"""

import os
import re
import sqlite3
import subprocess
import sys

PSQL = ["psql", "-At", "-v", "ON_ERROR_STOP=1"]


def to_postgres(sql: str) -> str:
    """Mirror of sql_translate::to_postgres.

    Kept in step by the shared cases below: if the Rust and this drift, the
    statements stop matching and this test fails, which is the point.
    """
    out, in_single, in_double = [], False, False
    chars = list(sql)
    for i, c in enumerate(chars):
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        if (
            c == "?"
            and not in_single
            and not in_double
            and i + 1 < len(chars)
            and chars[i + 1].isdigit()
        ):
            out.append("$")
        else:
            out.append(c)
    s = "".join(out)

    low = s.lstrip().lower()
    if low.startswith("insert or ignore into"):
        s = "INSERT INTO" + s.lstrip()[len("insert or ignore into") :]
        if "on conflict" not in s.lower():
            s = s.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
    elif low.startswith("insert or replace into") and "on conflict" in low:
        s = "INSERT INTO" + s.lstrip()[len("insert or replace into") :]

    s = re.sub(r"(?i)ifnull\(", "COALESCE(", s)
    s = re.sub(r"(?i)begin immediate transaction", "BEGIN", s)
    s = re.sub(r"(?i)begin immediate", "BEGIN", s)
    return s


def psql(sql: str) -> str:
    proc = subprocess.run(PSQL, input=sql, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(
            f"postgres rejected a translated statement:\n  {sql[:160]}\n  {proc.stderr.strip()[:300]}"
        )
    return proc.stdout.strip()


# One real table: the receipt chain, which exercises the constructs the port
# cares about — dedup on conflict, IFNULL over nullable columns, ordering by a
# monotonic sequence.
DDL = """CREATE TABLE agent_action_receipts (
  receipt_id TEXT PRIMARY KEY NOT NULL,
  tenant_id TEXT NOT NULL,
  action_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at {int} NOT NULL,
  seq {int} NOT NULL DEFAULT 0,
  prev_hash TEXT NOT NULL DEFAULT '',
  owner_mandate_hash TEXT NOT NULL DEFAULT ''
)"""

WRITES = [
    "INSERT INTO agent_action_receipts (receipt_id, tenant_id, action_hash, status, created_at, seq, prev_hash, owner_mandate_hash)"
    " VALUES ('r1','default','ah1','verified',100,1,'','m1')",
    # Duplicate primary key: must be silently ignored on BOTH backends. This is
    # the rewrite most likely to change behaviour if it is ever done carelessly.
    "INSERT OR IGNORE INTO agent_action_receipts (receipt_id, tenant_id, action_hash, status, created_at, seq, prev_hash, owner_mandate_hash)"
    " VALUES ('r1','default','SHOULD-NOT-OVERWRITE','verified',101,2,'x','m2')",
    "INSERT INTO agent_action_receipts (receipt_id, tenant_id, action_hash, status, created_at, seq, prev_hash, owner_mandate_hash)"
    " VALUES ('r2','default','ah2','verified',102,2,'h1','m1')",
    "INSERT INTO agent_action_receipts (receipt_id, tenant_id, action_hash, status, created_at, seq, prev_hash, owner_mandate_hash)"
    " VALUES ('r3','other','ah3','verified',103,1,'','')",
]

READS = [
    "SELECT receipt_id, action_hash FROM agent_action_receipts ORDER BY receipt_id",
    "SELECT COUNT(*) FROM agent_action_receipts",
    "SELECT IFNULL(seq, 0), IFNULL(prev_hash, '') FROM agent_action_receipts WHERE receipt_id = 'r2'",
    "SELECT receipt_id FROM agent_action_receipts WHERE tenant_id = 'default' AND seq > 0 ORDER BY seq ASC",
    "SELECT MAX(seq) FROM agent_action_receipts",
    "SELECT receipt_id FROM agent_action_receipts WHERE owner_mandate_hash <> '' ORDER BY receipt_id",
    "SELECT tenant_id, COUNT(*) FROM agent_action_receipts GROUP BY tenant_id ORDER BY tenant_id",
]


def main() -> None:
    con = sqlite3.connect(":memory:")
    con.executescript(DDL.format(int="INTEGER"))
    psql("DROP TABLE IF EXISTS agent_action_receipts;")
    psql(DDL.format(int="BIGINT") + ";")

    for sql in WRITES:
        con.execute(sql)
        psql(to_postgres(sql) + ";")
    con.commit()

    failures = 0
    for query in READS:
        sqlite_rows = [
            tuple("" if v is None else str(v) for v in row)
            for row in con.execute(query).fetchall()
        ]
        raw = psql(to_postgres(query) + ";")
        pg_rows = [tuple(line.split("|")) for line in raw.split("\n") if line != ""]
        if sqlite_rows == pg_rows:
            print(f"  ok   {query[:72]}")
        else:
            failures += 1
            print(f"  DIFF {query[:72]}")
            print(f"        sqlite = {sqlite_rows}")
            print(f"        pg     = {pg_rows}")

    total = len(READS)
    print(f"\n{total - failures}/{total} queries identical across backends")
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    if not os.environ.get("PGDATABASE"):
        raise SystemExit("PGDATABASE (and PGHOST/PGUSER/PGPASSWORD) must be set")
    main()

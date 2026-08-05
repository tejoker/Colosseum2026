#!/usr/bin/env python3
"""Prove every state-changing release job depends on independent-signoff."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else None
    if path is None or not path.is_file():
        raise SystemExit("usage: verify-release-dag.py <release-workflow.yml>")

    jobs: dict[str, set[str]] = {}
    current: str | None = None
    in_jobs = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "jobs:":
            in_jobs = True
            continue
        if not in_jobs:
            continue
        match = re.match(r"^  ([a-zA-Z0-9_-]+):\s*$", line)
        if match:
            current = match.group(1)
            jobs[current] = set()
            continue
        if current is None:
            continue
        match = re.match(r"^    needs:\s*(.+?)\s*$", line)
        if not match:
            continue
        raw = match.group(1)
        if raw.startswith("[") and raw.endswith("]"):
            deps = [item.strip() for item in raw[1:-1].split(",")]
        else:
            deps = [raw.strip()]
        jobs[current].update(dep for dep in deps if dep)

    required = {"tool-binaries", "wheels", "npm-tool", "images", "npm", "pypi", "github-release"}
    missing = required - jobs.keys()
    if missing:
        raise SystemExit(f"release workflow is missing jobs: {sorted(missing)}")

    def descends_from_signoff(job: str, seen: set[str] | None = None) -> bool:
        if job == "independent-signoff":
            return True
        seen = set() if seen is None else seen
        if job in seen:
            raise SystemExit(f"release dependency cycle at {job}")
        seen.add(job)
        return any(descends_from_signoff(dep, seen.copy()) for dep in jobs.get(job, set()))

    bypasses = sorted(job for job in required if not descends_from_signoff(job))
    if bypasses:
        raise SystemExit(f"publishing jobs bypass independent-signoff: {bypasses}")
    print("release publication DAG is sign-off bound")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

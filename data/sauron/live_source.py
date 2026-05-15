"""Live-data source for the SauronID analytics service.

Replaces the parquet path with HTTP calls to the live core. Every row
returned here is fresh from the SQL store at request time. **There is no
fallback to stale or stub data** — when the core is unreachable, we raise
`LiveSourceError` and the caller returns an HTTP 503 with a clear message.
This is the explicit contract of the Analytics 5/5 fix: numbers are either
live, or the dashboard says "core unreachable" — never silently stale.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Mapping, Optional

import httpx

logger = logging.getLogger(__name__)

SAURON_URL = os.getenv("SAURON_URL", "http://localhost:3001").rstrip("/")
ADMIN_KEY = os.environ.get("SAURON_ADMIN_KEY") or (_ for _ in ()).throw(
    RuntimeError(
        "SAURON_ADMIN_KEY is not set. Export it (or source .dev-secrets at the "
        "repo root) before importing live_source."
    )
)
TIMEOUT_SECS = float(os.getenv("SAURON_HTTP_TIMEOUT_SECS", "5"))


class LiveSourceError(RuntimeError):
    """Raised when the live core is unreachable or returns an error.

    Caller should map to HTTP 503 with the message — NEVER fall back to
    cached / stale data. The whole point of Analytics 5/5 is that dashboard
    numbers are either live or explicitly missing.
    """


def _admin_headers() -> dict:
    return {"x-admin-key": ADMIN_KEY}


def _get(path: str, *, params: Optional[Mapping[str, Any]] = None) -> Any:
    """GET an admin endpoint and return the parsed JSON. Raises on failure."""
    try:
        with httpx.Client(timeout=TIMEOUT_SECS) as client:
            r = client.get(
                f"{SAURON_URL}{path}",
                headers=_admin_headers(),
                params=params or None,
            )
    except httpx.HTTPError as exc:
        raise LiveSourceError(
            f"core unreachable at {SAURON_URL}{path}: {exc}"
        ) from exc
    if r.status_code >= 400:
        raise LiveSourceError(
            f"core HTTP {r.status_code} on {path}: {r.text[:200]}"
        )
    try:
        return r.json()
    except ValueError as exc:
        raise LiveSourceError(
            f"core returned non-JSON on {path}: {r.text[:200]}"
        ) from exc


# ─────────────────────────────────────────────────────────────────────────
# Public helpers — every analytics endpoint pulls from one of these.
# ─────────────────────────────────────────────────────────────────────────


def fetch_stats() -> dict:
    """High-level KPIs: total users, clients, agents, requests, etc."""
    return _get("/admin/stats")


def fetch_clients() -> list:
    return _get("/admin/clients")


def fetch_users() -> list:
    return _get("/admin/users")


def fetch_agents() -> list:
    """Every registered agent + checksum + revocation status + agent_type."""
    return _get("/admin/agents")


def fetch_recent_actions(limit: int = 200) -> list:
    return _get("/admin/agent_actions/recent", params={"limit": limit})


def fetch_recent_egress(limit: int = 200) -> list:
    return _get("/admin/egress/recent", params={"limit": limit})


def fetch_per_agent_metrics(limit: int = 50) -> list:
    return _get("/admin/per_agent_metrics", params={"limit": limit})


def fetch_anchor_status() -> dict:
    """Counts of pending vs upgraded BTC anchors and unconfirmed vs confirmed Solana anchors."""
    return _get("/admin/anchor/status")


def fetch_requests(limit: int = 200) -> list:
    return _get("/admin/requests", params={"limit": limit})


def fetch_health() -> dict:
    """Public /health (no admin key needed). Used to show the 'what's
    configured' panel in the dashboard."""
    try:
        with httpx.Client(timeout=TIMEOUT_SECS) as client:
            r = client.get(f"{SAURON_URL}/health")
            r.raise_for_status()
            return r.json()
    except httpx.HTTPError as exc:
        raise LiveSourceError(f"core /health unreachable: {exc}") from exc


def fetch_checksum_audit(agent_id: str) -> list:
    return _get(f"/admin/checksum/audit/{agent_id}")

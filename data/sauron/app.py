"""
Sauron internal dashboard — FastAPI app (port 8002)
"""
import asyncio
import csv
import json
import logging
import math
import os
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, time as dtime, timedelta
from pathlib import Path
from typing import AsyncIterator
from urllib.request import urlopen, Request as UrlRequest
from urllib.error import HTTPError as UrlHTTPError

import httpx
import numpy as np
import polars as pl
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from gdpr_purge import run_purge as _run_gdpr_purge

logger = logging.getLogger(__name__)

INGEST_URL  = os.getenv("INGEST_URL",  "http://localhost:8010")
SAURON_URL  = os.getenv("SAURON_URL",  "http://localhost:3001")
ADMIN_KEY   = os.environ.get("SAURON_ADMIN_KEY") or (_ for _ in ()).throw(
    RuntimeError(
        "SAURON_ADMIN_KEY is not set. Export it (or source .dev-secrets at the "
        "repo root) before starting the analytics service."
    )
)
DATA_DIR    = os.getenv("DATA_DIR",    str(Path(__file__).parent.parent))  # optional CSV exports (may be empty)

BASE    = Path(__file__).parent
DATA    = BASE / "data"

# ── Daily GDPR scheduler ─────────────────────────────────────────────────────
async def _gdpr_daily_scheduler() -> None:
    """Fires run_purge() every day at 02:00 local time."""
    while True:
        now    = datetime.now()
        target = datetime.combine(now.date(), dtime(2, 0))
        if now >= target:
            target = datetime.combine(now.date() + timedelta(days=1), dtime(2, 0))
        sleep_s = (target - now).total_seconds()
        logger.info("GDPR scheduler: next run in %.0fs (at %s)", sleep_s, target)
        await asyncio.sleep(sleep_s)
        try:
            result = _run_gdpr_purge()
            logger.info("GDPR daily purge done: %s", result)
            # Reload sauron_users so the API reflects new state
            global _sauron_users, _gdpr_log
            _sauron_users = pl.read_parquet(DATA / "sauron_users.parquet")
            _gdpr_log     = pl.read_parquet(DATA / "gdpr_log.parquet") if (DATA / "gdpr_log.parquet").exists() else pl.DataFrame()
        except Exception as exc:
            logger.exception("GDPR daily purge failed: %s", exc)

@asynccontextmanager
async def lifespan(app_: FastAPI):
    task = asyncio.create_task(_gdpr_daily_scheduler())
    yield
    task.cancel()

app = FastAPI(title="Sauron Analytics API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── lazy-loaded data ─────────────────────────────────────────────────────────
_clients       : pl.DataFrame | None = None
_credit_ledger : pl.DataFrame | None = None
_verifications : pl.DataFrame | None = None
_rings         : pl.DataFrame | None = None
_anomalies     : pl.DataFrame | None = None
_sauron_users  : pl.DataFrame | None = None
_gdpr_log      : pl.DataFrame | None = None

# Credit economy constants (dashboard KPI copy; keep aligned with core billing semantics)
CREDIT_A_PER_KYC = 1.0    # 1 Credit A per full KYC
KYC_USD_PER_HEAD = 2.00   # $2/KYC (1A = 5B, B = $0.40 → 1A = $2.00)
CREDIT_B_USD     = 0.40   # USD per Credit B
EXCHANGE_A_TO_B  = 5.0    # 1 Credit A = 5 Credit B

# Valid persona categories (optional CSV persona summaries only)
VALID_CATEGORIES = frozenset({"investment", "tech", "lifestyle", "food_living", "travel"})

# analytics (optional parquet tier under sauron/data/)
_client_scores   : pl.DataFrame | None = None
_runway_forecast : pl.DataFrame | None = None
_anomalies_ml    : pl.DataFrame | None = None
_revenue_forecast: pl.DataFrame | None = None
_cohort_analysis : pl.DataFrame | None = None
_ring_curves     : pl.DataFrame | None = None
_elasticity      : pl.DataFrame | None = None
_load_forecast   : pl.DataFrame | None = None

# ── Live state from Rust backend ─────────────────────────────────────────────
# Fetched on each request with a short TTL cache so the dashboard always
# reflects what is actually in the SQLite in-memory DB.
_live_state : dict | None = None
_live_ts    : float       = 0.0
_LIVE_TTL   : float       = 5.0   # seconds between refreshes

def _fetch_rust_state() -> dict:
    """Fetch live data from the Rust backend and cache it.
    Returns a dict with keys: stats, clients, users, requests.
    Falls back to stale cache (or empty) if backend is unreachable.
    """
    global _live_state, _live_ts
    import time
    now = time.time()
    if _live_state is not None and (now - _live_ts) < _LIVE_TTL:
        return _live_state
    try:
        with httpx.Client(timeout=3.0) as c:
            stats_r   = c.get(f"{SAURON_URL}/admin/stats",    headers={"x-admin-key": ADMIN_KEY})
            clients_r = c.get(f"{SAURON_URL}/admin/clients", headers={"x-admin-key": ADMIN_KEY})
            users_r   = c.get(f"{SAURON_URL}/admin/users",   headers={"x-admin-key": ADMIN_KEY})
            reqs_r    = c.get(f"{SAURON_URL}/admin/requests",headers={"x-admin-key": ADMIN_KEY})
        _live_state = {
            "stats":    stats_r.json()   if stats_r.is_success   else {},
            "clients":  clients_r.json() if clients_r.is_success else [],
            "users":    users_r.json()   if users_r.is_success   else [],
            "requests": reqs_r.json()    if reqs_r.is_success    else [],
        }
        _live_ts = now
        logger.debug("[live] fetched from Rust: %d clients, %d users",
                     len(_live_state["clients"]), len(_live_state["users"]))
    except Exception as exc:
        logger.warning("Rust backend unreachable: %s", exc)
        if _live_state is None:
            _live_state = {"stats": {}, "clients": [], "users": [], "requests": []}
    return _live_state


def _build_minimal_from_rust() -> None:
    """Build stub DataFrames from Rust live data when parquets are unavailable."""
    global _clients, _credit_ledger, _verifications, _rings, _anomalies, _sauron_users, _gdpr_log
    live = _fetch_rust_state()
    rust_clients = live.get("clients", [])
    rust_users   = live.get("users",   [])

    _clients = pl.DataFrame(
        [{"client_id": i + 1, "name": c["name"], "type": c["client_type"],
          "sector": "unknown", "country": "unknown", "join_date": "2025-01-01"}
         for i, c in enumerate(rust_clients)]
    ) if rust_clients else pl.DataFrame(
        schema={"client_id": pl.Int64, "name": pl.Utf8, "type": pl.Utf8,
                "sector": pl.Utf8, "country": pl.Utf8, "join_date": pl.Utf8}
    )

    # Empty stubs so chart code doesn't crash
    _credit_ledger = pl.DataFrame(schema={
        "client_id": pl.Int64, "date": pl.Utf8, "credit_type": pl.Utf8,
        "event_type": pl.Utf8, "amount": pl.Float64, "balance_after": pl.Float64,
    })
    _verifications = pl.DataFrame(schema={
        "client_id": pl.Int64, "date": pl.Utf8, "full_kyc": pl.Int64,
        "reduced": pl.Int64, "failed": pl.Int64, "total": pl.Int64,
    })
    _rings = pl.DataFrame(schema={
        "ring_id": pl.Utf8, "date": pl.Utf8,
        "ring_label": pl.Utf8, "member_count": pl.Int64,
    })
    _anomalies = pl.DataFrame(schema={
        "client_id": pl.Int64, "date": pl.Utf8,
        "anomaly_type": pl.Utf8, "severity": pl.Utf8, "detail": pl.Utf8,
    })

    _sauron_users = pl.DataFrame(
        [{"first_name": u["first_name"], "last_name": u["last_name"],
          "country": u["nationality"], "is_anonymized": False,
          "last_auth_date": "2025-01-01"}
         for u in rust_users]
    ) if rust_users else pl.DataFrame(schema={
        "first_name": pl.Utf8, "last_name": pl.Utf8, "country": pl.Utf8,
        "is_anonymized": pl.Boolean, "last_auth_date": pl.Utf8,
    })
    _gdpr_log = pl.DataFrame()


def _load():
    global _clients, _credit_ledger, _verifications, _rings, _anomalies
    global _sauron_users, _gdpr_log
    if _clients is not None:
        return
    try:
        _clients       = pl.read_parquet(DATA / "clients.parquet")
        _credit_ledger = pl.read_parquet(DATA / "credit_ledger.parquet")
        _verifications = pl.read_parquet(DATA / "verifications.parquet")
        _rings         = pl.read_parquet(DATA / "ring_snapshots.parquet")
        _anomalies     = pl.read_parquet(DATA / "anomaly_events.parquet")
        _sauron_users  = pl.read_parquet(DATA / "sauron_users.parquet")
        _gdpr_log      = pl.read_parquet(DATA / "gdpr_log.parquet") if (DATA / "gdpr_log.parquet").exists() else pl.DataFrame()
        logger.info("[load] parquets loaded (%d clients, %d users)",
                    _clients.height, _sauron_users.height)
    except Exception as exc:
        logger.warning("[load] parquets unavailable (%s) — falling back to Rust live data", exc)
        _build_minimal_from_rust()

def _init_insight_frames_empty(reason: str) -> None:
    """Optional ML-insights parquet tier (historical charts). Product truth is Rust core + real ops data."""
    global _client_scores, _runway_forecast, _anomalies_ml, _revenue_forecast
    global _cohort_analysis, _ring_curves, _elasticity, _load_forecast
    logger.info("ML insight parquets unavailable (%s) — using empty insight frames", reason)
    _client_scores = pl.DataFrame(
        {
            "client_id": pl.Series([], dtype=pl.Int64),
            "churn_risk": pl.Series([], dtype=pl.Float64),
            "trust_score": pl.Series([], dtype=pl.Float64),
            "health_score": pl.Series([], dtype=pl.Float64),
        }
    )
    _runway_forecast = pl.DataFrame(
        {
            "client_id": pl.Series([], dtype=pl.Int64),
            "runway_days": pl.Series([], dtype=pl.Float64),
            "burn_rate": pl.Series([], dtype=pl.Float64),
            "projected_depletion": pl.Series([], dtype=pl.Utf8),
            "current_balance": pl.Series([], dtype=pl.Float64),
        }
    )
    _anomalies_ml = pl.DataFrame(
        {
            "client_id": pl.Series([], dtype=pl.Int64),
            "date": pl.Series([], dtype=pl.Utf8),
            "anomaly_type": pl.Series([], dtype=pl.Utf8),
            "severity": pl.Series([], dtype=pl.Utf8),
            "anomaly_score": pl.Series([], dtype=pl.Float64),
            "message": pl.Series([], dtype=pl.Utf8),
        }
    )
    _revenue_forecast = pl.DataFrame(
        {
            "month": pl.Series([], dtype=pl.Utf8),
            "revenue_actual": pl.Series([], dtype=pl.Float64),
            "revenue_forecast": pl.Series([], dtype=pl.Float64),
            "ci_lo": pl.Series([], dtype=pl.Float64),
            "ci_hi": pl.Series([], dtype=pl.Float64),
            "is_forecast": pl.Series([], dtype=pl.Boolean),
        }
    )
    _cohort_analysis = pl.DataFrame(
        {
            "cohort": pl.Series([], dtype=pl.Utf8),
            "month": pl.Series([], dtype=pl.Utf8),
            "vol_per_client": pl.Series([], dtype=pl.Float64),
            "cohort_size": pl.Series([], dtype=pl.Int64),
        }
    )
    _ring_curves = pl.DataFrame(
        {
            "ring_label": pl.Series([], dtype=pl.Utf8),
            "saturation_pct": pl.Series([], dtype=pl.Float64),
        }
    )
    _elasticity = pl.DataFrame(
        {
            "metric": pl.Series([], dtype=pl.Utf8),
            "value": pl.Series([], dtype=pl.Float64),
            "p_value": pl.Series([], dtype=pl.Float64),
            "description": pl.Series([], dtype=pl.Utf8),
        }
    )
    _load_forecast = pl.DataFrame(
        {
            "date": pl.Series([], dtype=pl.Utf8),
            "load_actual": pl.Series([], dtype=pl.Float64),
            "load_forecast": pl.Series([], dtype=pl.Float64),
            "is_forecast": pl.Series([], dtype=pl.Boolean),
        }
    )


def _load_analytics():
    global _client_scores, _runway_forecast, _anomalies_ml
    global _revenue_forecast, _cohort_analysis, _ring_curves
    global _elasticity, _load_forecast
    if _client_scores is not None:
        return
    marker = DATA / "client_scores.parquet"
    if not marker.exists():
        _init_insight_frames_empty("no optional analytics parquets under sauron/data/")
        return
    try:
        _client_scores = pl.read_parquet(DATA / "client_scores.parquet")
        _runway_forecast = pl.read_parquet(DATA / "runway_forecast.parquet")
        _anomalies_ml = pl.read_parquet(DATA / "anomalies_ml.parquet")
        _revenue_forecast = pl.read_parquet(DATA / "revenue_forecast.parquet")
        _cohort_analysis = pl.read_parquet(DATA / "cohort_analysis.parquet")
        _ring_curves = pl.read_parquet(DATA / "ring_curves.parquet")
        _elasticity = pl.read_parquet(DATA / "elasticity.parquet")
        _load_forecast = pl.read_parquet(DATA / "load_forecast.parquet")
    except Exception as exc:
        logger.warning("analytics parquet load failed: %s", exc)
        _init_insight_frames_empty(str(exc))


# ── API: overview ─────────────────────────────────────────────────────────────
@app.get("/api/overview")
def api_overview():
    _load()

    # ── KPIs: prefer optional local parquets when present; otherwise Rust live SQLite. ──

    unique_users        = int(_sauron_users.height) if _sauron_users is not None and _sauron_users.height > 0 else 0
    total_clients_live  = int(_clients.height) if _clients is not None else 0

    # Credit A: total earned from parquet KYC events
    parquet_a_earned    = float(_credit_ledger.filter((pl.col("credit_type") == "A") & (pl.col("amount") > 0))["amount"].sum()) if _credit_ledger.height > 0 else 0.0
    # Credit A burned (converted to B)
    parquet_a_burned    = float(_credit_ledger.filter(pl.col("event_type") == "convert_to_B")["amount"].abs().sum()) if _credit_ledger.height > 0 else 0.0
    credit_a_retained   = round(parquet_a_earned - parquet_a_burned, 1)

    # Credit B
    parquet_b_purchased = float(_credit_ledger.filter((pl.col("credit_type") == "B") & (pl.col("event_type") == "purchase"))["amount"].sum()) if _credit_ledger.height > 0 else 0.0
    parquet_b_converted = float(_credit_ledger.filter(pl.col("event_type") == "convert_from_A")["amount"].sum()) if _credit_ledger.height > 0 else 0.0
    parquet_b_issued    = parquet_b_purchased + parquet_b_converted
    parquet_b_spent     = float(_credit_ledger.filter(pl.col("event_type") == "verify_spent")["amount"].abs().sum()) if _credit_ledger.height > 0 else 0.0

    credit_b_face_value = round(parquet_b_issued * CREDIT_B_USD, 2)
    kyc_revenue         = round(parquet_a_earned * KYC_USD_PER_HEAD, 2)
    query_revenue       = round(parquet_b_spent * CREDIT_B_USD, 2)

    # ── Historical chart data from parquets (decorative) ──────────────────
    total_verif = int(_verifications["total"].sum())   if _verifications.height > 0 else 0
    total_full  = int(_verifications["full_kyc"].sum()) if _verifications.height > 0 else 0
    total_red   = int(_verifications["reduced"].sum())  if _verifications.height > 0 else 0
    total_fail  = int(_verifications["failed"].sum())   if _verifications.height > 0 else 0

    # GDPR pending (based on real users in Rust)
    gdpr_pending = 0
    if _sauron_users is not None and _sauron_users.height > 0:
        from gdpr_purge import EU_EEA_COUNTRIES
        gdpr_pending = int(_sauron_users.filter(
            pl.col("country").is_in(list(EU_EEA_COUNTRIES)) &
            (pl.col("is_anonymized") == False)
        ).height)

    # Active client window (parquet decorative; fallback = live total)
    active_clients: int
    if _verifications.height > 0:
        max_date_str  = _verifications["date"].max()
        from datetime import date as _date
        _max_d        = _date.fromisoformat(max_date_str)
        _cutoff_90d   = (_max_d - timedelta(days=90)).isoformat()
        _cutoff_chart = _cutoff_90d
        active_clients = int(
            _verifications.filter(pl.col("date") >= _cutoff_90d)
            .select("client_id").unique().height
        )
    else:
        from datetime import date as _date, timedelta as _td
        _max_d        = _date.today()
        _cutoff_chart = (_max_d - timedelta(days=90)).isoformat()
        active_clients = total_clients_live

    # daily Credit A earned and Credit B spent – last 90 days
    recent_a = (
        _credit_ledger
        .filter(
            (pl.col("date") >= _cutoff_chart) &
            (pl.col("credit_type") == "A") &
            (pl.col("event_type") == "kyc_earned")
        )
        .group_by("date")
        .agg(pl.sum("amount").alias("credit_a"))
        .sort("date")
    )
    recent_b = (
        _credit_ledger
        .filter(
            (pl.col("date") >= _cutoff_chart) &
            (pl.col("credit_type") == "B") &
            (pl.col("event_type") == "verify_spent")
        )
        .group_by("date")
        .agg(pl.sum("amount").alias("credit_b"))
        .sort("date")
    )
    recent = (
        recent_a.join(recent_b, on="date", how="outer_coalesce")
        .sort("date")
        .with_columns([
            pl.col("credit_a").fill_null(0.0),
            pl.col("credit_b").fill_null(0.0),
        ])
    )
    # ring sizes (latest snapshot — empty if no parquet)
    if _rings.height > 0:
        latest_ring = (
            _rings.sort("date")
            .group_by("ring_id")
            .agg(
                pl.last("ring_label").alias("label"),
                pl.last("member_count").alias("count"),
            )
            .sort("ring_id")
        )
    else:
        latest_ring = pl.DataFrame(schema={"ring_id": pl.Utf8, "label": pl.Utf8, "count": pl.Int64})

    return {
        "kpis": {
            "total_verifications":    total_verif,
            "total_full_kyc":         total_full,
            "total_reduced":          total_red,
            "total_failed":           total_fail,
            "failure_rate":           round(total_fail / max(total_verif, 1) * 100, 2),
            "active_clients":         active_clients,
            # ── All from parquet simulation data ──────────────────────
            "unique_registered_users": unique_users,
            "total_clients":          total_clients_live,
            "kyc_revenue_usd":        kyc_revenue,
            "query_revenue_usd":      query_revenue,
            "credit_a_total_minted":  round(parquet_a_earned, 0),
            "credit_a_retained":      credit_a_retained,
            "credit_a_earned":        round(parquet_a_earned, 0),
            "credit_b_issued":        round(parquet_b_issued, 0),
            "credit_b_purchased":     round(parquet_b_purchased, 0),
            "credit_b_face_value":    credit_b_face_value,
            "exchange_rate":          EXCHANGE_A_TO_B,
            "gdpr_pending":           gdpr_pending,
        },
        "daily": {
            "dates":    recent["date"].to_list()    if recent.height > 0 else [],
            "credit_a": [round(v, 1) for v in recent["credit_a"].to_list()] if recent.height > 0 else [],
            "credit_b": [round(abs(v), 1) for v in recent["credit_b"].to_list()] if recent.height > 0 else [],
        },
        "rings": {
            "labels": latest_ring["ring_id"].to_list() if latest_ring.height > 0 else [],
            "names":  latest_ring["label"].to_list()   if latest_ring.height > 0 else [],
            "counts": latest_ring["count"].to_list()   if latest_ring.height > 0 else [],
        },
    }


# ── API: credits ───────────────────────────────────────────────────────────────
@app.get("/api/tokens")
def api_tokens():
    _load()

    # ── Credit data from parquets (consistent with overview) ─────────────
    live  = _fetch_rust_state()
    stats = live.get("stats", {})
    # Index live clients by name for balance lookups
    live_by_name: dict[str, dict] = {c["name"]: c for c in live.get("clients", [])}

    # All credit aggregates from parquet (not Rust seed data)
    parquet_a_earned   = float(_credit_ledger.filter((pl.col("credit_type") == "A") & (pl.col("amount") > 0))["amount"].sum()) if _credit_ledger.height > 0 else 0.0
    parquet_a_burned   = float(_credit_ledger.filter(pl.col("event_type") == "convert_to_B")["amount"].abs().sum()) if _credit_ledger.height > 0 else 0.0
    parquet_b_purchased= float(_credit_ledger.filter((pl.col("credit_type") == "B") & (pl.col("event_type") == "purchase"))["amount"].sum()) if _credit_ledger.height > 0 else 0.0
    parquet_b_converted= float(_credit_ledger.filter(pl.col("event_type") == "convert_from_A")["amount"].sum()) if _credit_ledger.height > 0 else 0.0
    parquet_b_issued   = parquet_b_purchased + parquet_b_converted
    parquet_b_spent    = float(_credit_ledger.filter(pl.col("event_type") == "verify_spent")["amount"].abs().sum()) if _credit_ledger.height > 0 else 0.0
    credit_a_retained  = round(parquet_a_earned - parquet_a_burned, 1)
    credit_b_face_value= round(parquet_b_issued * CREDIT_B_USD, 2)
    kyc_revenue        = round(parquet_a_earned * KYC_USD_PER_HEAD, 2)
    query_revenue      = round(parquet_b_spent * CREDIT_B_USD, 2)

    # ── Per-client B spent (30d window and all-time) from parquet ──────
    max_date_str = _credit_ledger["date"].max() if _credit_ledger.height > 0 else "2025-12-31"
    from datetime import date as _date
    _max_d      = _date.fromisoformat(max_date_str)
    _cutoff_30d = (_max_d - timedelta(days=30)).isoformat()

    per_client_b_30d = (
        _credit_ledger.filter(
            (pl.col("event_type") == "verify_spent") &
            (pl.col("date") >= _cutoff_30d)
        )
        .group_by("client_id")
        .agg(pl.sum("amount").abs().alias("b_spent_30d"))
    ) if _credit_ledger.height > 0 else pl.DataFrame(schema={"client_id": pl.Int64, "b_spent_30d": pl.Float64})

    per_client_a_30d = (
        _credit_ledger.filter(
            (pl.col("event_type") == "kyc_earned") &
            (pl.col("date") >= _cutoff_30d)
        )
        .group_by("client_id")
        .agg(pl.sum("amount").alias("a_earned_30d"))
    ) if _credit_ledger.height > 0 else pl.DataFrame(schema={"client_id": pl.Int64, "a_earned_30d": pl.Float64})

    # Per-client all-time B spent for burn rate
    per_client_b_all = (
        _credit_ledger.filter(pl.col("event_type") == "verify_spent")
        .group_by("client_id")
        .agg(pl.sum("amount").abs().alias("b_spent_total"))
    ) if _credit_ledger.height > 0 else pl.DataFrame(schema={"client_id": pl.Int64, "b_spent_total": pl.Float64})

    # Build lookup dicts
    b30d_map  = {r["client_id"]: r["b_spent_30d"]  for r in per_client_b_30d.iter_rows(named=True)}
    a30d_map  = {r["client_id"]: r["a_earned_30d"] for r in per_client_a_30d.iter_rows(named=True)}
    btot_map  = {r["client_id"]: r["b_spent_total"] for r in per_client_b_all.iter_rows(named=True)}

    # Data spans ~24 months
    total_months = max(1, len(set(
        _credit_ledger["date"].str.slice(0, 7).to_list()
    ))) if _credit_ledger.height > 0 else 1

    # ── Per-client token balances ──────────────────────────────────────────
    clients_out = []
    for row in _clients.iter_rows(named=True):
        name  = row["name"]
        ctype = row["type"]
        cid   = row["client_id"]
        lc    = live_by_name.get(name, {})
        ba    = float(lc.get("tokens_a", 0))
        bb    = float(lc.get("tokens_b", 0))
        is_issuer = (ctype == "FULL_KYC")
        client_b_30d = b30d_map.get(cid, 0.0)
        client_a_30d = a30d_map.get(cid, 0.0)

        # Runway: use all-time average monthly burn rate (most representative
        # of the 2-year simulation).  30-day rate used only if higher (shorter runway).
        client_b_total = btot_map.get(cid, 0.0)
        avg_daily_burn = client_b_total / total_months / 30.0 if client_b_total > 0 else 0
        recent_daily   = client_b_30d / 30.0
        daily_burn     = max(avg_daily_burn, recent_daily)  # conservative: pick higher burn
        runway = round(bb / daily_burn, 1) if daily_burn > 0 else 9999

        if is_issuer:
            runway = 9999  # issuers don't consume B

        clients_out.append({
            "client_id":    cid,
            "name":         name,
            "type":         ctype,
            "bal_a":        ba,
            "bal_b":        bb,
            "a_earned_30d": round(client_a_30d, 1),
            "b_spent_30d":  round(client_b_30d, 1),
            "runway_days":  runway,
        })

    low_b = [c for c in clients_out if c["bal_b"] < 20 and c["type"] == "ZKP_ONLY"]

    # ── Historical chart data from parquets ──────────────────────────────
    if _credit_ledger.height > 0:
        monthly_conv = (
            _credit_ledger.filter(pl.col("event_type") == "convert_from_A")
            .with_columns(pl.col("date").str.slice(0, 7).alias("month"))
            .group_by("month")
            .agg(pl.sum("amount").alias("credit_b_converted"))
            .sort("month")
        )
        monthly_a = (
            _credit_ledger.filter((pl.col("credit_type") == "A") & (pl.col("amount") > 0))
            .with_columns(pl.col("date").str.slice(0, 7).alias("month"))
            .group_by("month")
            .agg(pl.sum("amount").alias("credit_a"))
            .sort("month")
        )
    else:
        monthly_conv = pl.DataFrame(schema={"month": pl.Utf8, "credit_b_converted": pl.Float64})
        monthly_a    = pl.DataFrame(schema={"month": pl.Utf8, "credit_a": pl.Float64})

    return {
        "credit_summary": {
            # ─ All from parquet simulation data ─
            "credit_a_total_minted":  round(parquet_a_earned, 0),
            "credit_a_converted":     round(parquet_a_burned, 0),
            "credit_a_retained":      credit_a_retained,
            "credit_b_issued":        round(parquet_b_issued, 0),
            "credit_b_spent":         round(parquet_b_spent, 0),
            "credit_b_converted":     round(parquet_b_converted, 0),
            "credit_b_face_value":    credit_b_face_value,
            "exchange_rate":          EXCHANGE_A_TO_B,
            "credit_b_usd":           CREDIT_B_USD,
            "kyc_revenue_usd":        kyc_revenue,
            "kyc_revenue_gross":       kyc_revenue,
            "query_revenue_usd":       query_revenue,
        },
        "clients":            clients_out,
        "low_balance_alerts": low_b,
        "monthly_credit_a": {
            "months":   monthly_a["month"].to_list()   if monthly_a.height > 0 else [],
            "credit_a": monthly_a["credit_a"].to_list() if monthly_a.height > 0 else [],
        },
        "monthly_conversions": {
            "months":             monthly_conv["month"].to_list()            if monthly_conv.height > 0 else [],
            "credit_b_converted": monthly_conv["credit_b_converted"].to_list() if monthly_conv.height > 0 else [],
        },
    }


# ── API: credits per client ──────────────────────────────────────────────
@app.get("/api/tokens/{client_id}")
def api_tokens_client(client_id: int):
    _load()
    events = (
        _credit_ledger
        .filter(pl.col("client_id") == client_id)
        .sort("date")
    )
    if events.is_empty():
        raise HTTPException(status_code=404, detail="Client not found")
    client = _clients.filter(pl.col("client_id") == client_id).row(0, named=True)
    return {
        "client_id": client_id,
        "name":      client["name"],
        "type":      client["type"],
        "events":    events.select(["date","credit_type","event_type","amount","balance_after"]).to_dicts(),
        "dates":     events["date"].to_list(),
        "balance":   events["balance_after"].to_list(),
    }


# ── API: verifications ────────────────────────────────────────────────────────
@app.get("/api/verifications")
def api_verifications():
    _load()

    has_split = "initial_kyc" in _verifications.schema

    # Monthly totals platform-wide
    agg_cols = [
        pl.sum("full_kyc").alias("full_kyc"),
        pl.sum("reduced").alias("reduced"),
        pl.sum("failed").alias("failed"),
        pl.sum("total").alias("total"),
    ]
    if has_split:
        agg_cols += [
            pl.sum("initial_kyc").alias("initial_kyc"),
            pl.sum("rekyc").alias("rekyc"),
        ]

    monthly = (
        _verifications
        .with_columns(pl.col("date").str.slice(0, 7).alias("month"))
        .group_by("month")
        .agg(agg_cols)
        .sort("month")
    )

    # Per-type totals (FULL_KYC vs ZKP_ONLY)
    with_type = _verifications.join(
        _clients.select(["client_id","type","name"]), on="client_id"
    )
    by_type = (
        with_type.group_by("type")
        .agg(pl.sum("total").alias("total"))
    )

    # Per-client totals for table
    per_client_agg = [
        pl.sum("full_kyc").alias("full_kyc"),
        pl.sum("reduced").alias("reduced"),
        pl.sum("total").alias("total"),
        pl.sum("failed").alias("failed"),
    ]
    if has_split:
        per_client_agg += [
            pl.sum("initial_kyc").alias("initial_kyc"),
            pl.sum("rekyc").alias("rekyc"),
        ]
    per_client = (
        _verifications
        .group_by("client_id")
        .agg(per_client_agg)
        .join(_clients.select(["client_id","name","type"]), on="client_id")
        .with_columns(
            (pl.col("failed") / (pl.col("total") + 1) * 100).round(1).alias("fail_rate")
        )
        .sort("total", descending=True)
    )

    type_map = {r["type"]: r["total"] for r in by_type.iter_rows(named=True)}

    result = {
        "has_split": has_split,
        "monthly": {
            "months":   monthly["month"].to_list(),
            "full_kyc": monthly["full_kyc"].to_list(),
            "reduced":  monthly["reduced"].to_list(),
            "failed":   monthly["failed"].to_list(),
            "total":    monthly["total"].to_list(),
        },
        "by_type": type_map,
        "per_client": per_client.to_dicts(),
    }
    if has_split:
        result["monthly"]["initial_kyc"] = monthly["initial_kyc"].to_list()
        result["monthly"]["rekyc"] = monthly["rekyc"].to_list()
    return result


# ── API: rings ────────────────────────────────────────────────────────────────
@app.get("/api/rings")
def api_rings():
    _load()
    ring_ids = _rings["ring_id"].unique().sort().to_list()

    series: dict[str, dict] = {}
    for rid in ring_ids:
        rows = _rings.filter(pl.col("ring_id") == rid).sort("date")
        label = rows["ring_label"][0]
        series[rid] = {
            "label":  label,
            "dates":  rows["date"].to_list(),
            "counts": rows["member_count"].to_list(),
        }

    # Latest snapshot
    latest = (
        _rings.sort("date")
        .group_by("ring_id")
        .agg(
            pl.last("ring_label").alias("label"),
            pl.last("member_count").alias("count"),
            pl.first("member_count").alias("first_count"),
        )
        .with_columns(
            pl.when(pl.col("first_count") > 0)
            .then(((pl.col("count") - pl.col("first_count")) / pl.col("first_count") * 100).round(1))
            .otherwise(pl.lit(None))
            .alias("growth_pct")
        )
        .sort("ring_id")
    )

    return {
        "series": series,
        "latest": latest.to_dicts(),
    }


# ── API: clients ──────────────────────────────────────────────────────────────
@app.get("/api/clients")
def api_clients():
    _load()

    # ── Live token balances from Rust (keyed by name) ──────────────────────
    live         = _fetch_rust_state()
    live_by_name = {c["name"]: c for c in live.get("clients", [])}

    # Decorative: last activity and total verifications from parquets
    if _verifications.height > 0:
        last_activity = (
            _verifications.sort("date")
            .group_by("client_id")
            .agg(pl.last("date").alias("last_active"))
        )
        total_verif_df = (
            _verifications.group_by("client_id")
            .agg(pl.sum("total").alias("total_verifications"))
        )
    else:
        last_activity  = pl.DataFrame(schema={"client_id": pl.Int64, "last_active": pl.Utf8})
        total_verif_df = pl.DataFrame(schema={"client_id": pl.Int64, "total_verifications": pl.Int64})

    rows_out = []
    for row in _clients.iter_rows(named=True):
        name = row["name"]
        lc   = live_by_name.get(name, {})
        rows_out.append({
            "client_id": row["client_id"],
            # ─ LIVE from Rust ─
            "balance_a": float(lc.get("tokens_a", 0)),
            "balance_b": float(lc.get("tokens_b", 0)),
        })

    bal_df = pl.DataFrame(rows_out)
    result = (
        _clients
        .join(bal_df,          on="client_id", how="left")
        .join(last_activity,   on="client_id", how="left")
        .join(total_verif_df,  on="client_id", how="left")
        .with_columns([
            pl.col("balance_a").fill_null(0),
            pl.col("balance_b").fill_null(0),
            pl.col("total_verifications").fill_null(0),
            pl.col("last_active").fill_null("never"),
        ])
        .sort("total_verifications", descending=True)
    )

    return {"clients": result.to_dicts()}


@app.get("/api/clients/{client_id}")
def api_client_detail(client_id: int):
    _load()
    c = _clients.filter(pl.col("client_id") == client_id)
    if c.is_empty():
        raise HTTPException(status_code=404, detail="Client not found")
    client = c.row(0, named=True)

    # Verification history (monthly)
    monthly = (
        _verifications.filter(pl.col("client_id") == client_id)
        .with_columns(pl.col("date").str.slice(0, 7).alias("month"))
        .group_by("month")
        .agg(
            pl.sum("full_kyc").alias("full_kyc"),
            pl.sum("reduced").alias("reduced"),
            pl.sum("total").alias("total"),
        )
        .sort("month")
    )

    # Credit history
    credit_events = (
        _credit_ledger.filter(pl.col("client_id") == client_id)
        .sort("date")
    )

    return {
        "client": client,
        "monthly_verifications": monthly.to_dicts(),
        "credit_events": credit_events.select(["date","credit_type","event_type","amount","balance_after"]).to_dicts(),
    }


# ── API: anomalies ────────────────────────────────────────────────────────────
@app.get("/api/anomalies")
def api_anomalies():
    _load()

    with_client = (
        _anomalies
        .join(_clients.select(["client_id","name","type"]), on="client_id")
        .sort("date", descending=True)
    )

    # Counts by type
    by_type = (
        _anomalies.group_by("anomaly_type")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
    )

    # Counts by severity
    by_severity = (
        _anomalies.group_by("severity")
        .agg(pl.len().alias("count"))
    )

    # Monthly count
    monthly = (
        _anomalies
        .with_columns(pl.col("date").str.slice(0, 7).alias("month"))
        .group_by("month")
        .agg(pl.len().alias("count"))
        .sort("month")
    )

    return {
        "events": with_client.head(200).to_dicts(),
        "by_type": by_type.to_dicts(),
        "by_severity": by_severity.to_dicts(),
        "monthly": {
            "months": monthly["month"].to_list(),
            "counts": monthly["count"].to_list(),
        },
    }


# ── API: insights (analytics) ─────────────────────────────────────────────────

def _ser(v):
    """JSON-safe serialiser for numpy / polars types."""
    if isinstance(v, (np.integer,)):       return int(v)
    if isinstance(v, (np.floating,)):      return float(v)
    if isinstance(v, (np.bool_,)):         return bool(v)
    return v

def _df_to_dicts(df: pl.DataFrame) -> list:
    rows = df.to_dicts()
    return [{k: _ser(val) for k, val in r.items()} for r in rows]


@app.get("/api/insights/clients")
def api_insights_clients():
    _load()
    _load_analytics()
    joined = (
        _client_scores
        .join(_clients.select(["client_id","name","type","sector","country"]), on="client_id")
        .join(_runway_forecast.select(["client_id","runway_days","burn_rate",
                                       "projected_depletion","current_balance"]), on="client_id")
        .sort("churn_risk", descending=True)
    )
    return {"clients": _df_to_dicts(joined)}


@app.get("/api/insights/forecast")
def api_insights_forecast():
    _load_analytics()
    rows = _df_to_dicts(_revenue_forecast)
    actual    = [r for r in rows if not r["is_forecast"]]
    forecast  = [r for r in rows if r["is_forecast"]]
    return {"actual": actual, "forecast": forecast}


@app.get("/api/insights/anomalies-ml")
def api_insights_anomalies_ml():
    _load()
    _load_analytics()
    if _anomalies_ml is None or _anomalies_ml.is_empty():
        return {"events": [], "by_type": [], "by_severity": [], "total": 0}
    with_client = (
        _anomalies_ml
        .join(_clients.select(["client_id","name","type"]), on="client_id")
        .sort("date", descending=True)
    )
    by_type = (
        _anomalies_ml.group_by("anomaly_type")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
    )
    by_sev = (
        _anomalies_ml.group_by("severity")
        .agg(pl.len().alias("count"))
    )
    return {
        "events":      _df_to_dicts(with_client.head(300)),
        "by_type":     _df_to_dicts(by_type),
        "by_severity": _df_to_dicts(by_sev),
        "total":       len(_anomalies_ml),
    }


@app.get("/api/insights/rings")
def api_insights_rings():
    _load_analytics()
    return {"curves": _df_to_dicts(_ring_curves)}


@app.get("/api/insights/cohorts")
def api_insights_cohorts():
    _load_analytics()
    cohorts  = sorted(_cohort_analysis["cohort"].unique().to_list())
    months   = sorted(_cohort_analysis["month"].unique().to_list())
    # build matrix [cohort][month] = vol_per_client
    matrix = {}
    for r in _cohort_analysis.iter_rows(named=True):
        matrix.setdefault(r["cohort"], {})[r["month"]] = r["vol_per_client"]
    # fill None for missing cells
    grid = []
    for c in cohorts:
        grid.append([matrix.get(c, {}).get(m) for m in months])
    cohort_sizes = (
        _cohort_analysis
        .group_by("cohort")
        .agg(pl.col("cohort_size").first())
        .sort("cohort")
        .to_dicts()
    )
    return {"cohorts": cohorts, "months": months, "grid": grid, "sizes": cohort_sizes}


@app.get("/api/insights/load")
def api_insights_load():
    _load_analytics()
    rows = _df_to_dicts(_load_forecast)
    hist     = [r for r in rows if not r["is_forecast"]]
    forecast = [r for r in rows if r["is_forecast"]]
    return {"historical": hist, "forecast": forecast}


@app.get("/api/insights/elasticity")
def api_insights_elasticity():
    _load_analytics()
    return {"metrics": _df_to_dicts(_elasticity)}


@app.get("/api/insights")
def api_insights_summary():
    _load()
    _load_analytics()
    # high-risk clients (churn > 50%)
    at_risk = (
        _client_scores
        .filter(pl.col("churn_risk") > 0.5)
        .join(_clients.select(["client_id","name","type"]), on="client_id")
        .sort("churn_risk", descending=True)
        .head(10)
    )
    def _mean_or_zero(col: str) -> float:
        if _client_scores.height == 0:
            return 0.0
        m = _client_scores[col].mean()
        if m is None:
            return 0.0
        mf = float(m)
        return 0.0 if math.isnan(mf) else mf

    avg_churn = _mean_or_zero("churn_risk")
    avg_trust = _mean_or_zero("trust_score")
    ml_anom    = len(_anomalies_ml)
    ring_stats = _ring_curves.select(["ring_label","saturation_pct"]).to_dicts()

    return {
        "avg_churn_risk":       round(avg_churn, 4),
        "avg_trust_score":      round(avg_trust, 1),
        "ml_anomalies_detected":ml_anom,
        "at_risk_clients":      _df_to_dicts(at_risk),
        "ring_saturation":      ring_stats,
    }


# ── GDPR data retention ───────────────────────────────────────────────────────

@app.get("/api/gdpr/stats")
def gdpr_stats():
    _load()
    from gdpr_purge import EU_EEA_COUNTRIES

    today     = datetime.now().date()
    cutoff    = str(today - timedelta(days=365))
    total     = int(_sauron_users.height)
    anonymized = int(_sauron_users.filter(pl.col("is_anonymized")).height)

    eu_mask       = pl.col("country").is_in(list(EU_EEA_COUNTRIES)) \
                    if "country" in _sauron_users.schema \
                    else pl.lit(True)
    eu_eea_total  = int(_sauron_users.filter(eu_mask).height)
    non_eu_total  = total - eu_eea_total

    eligible = int(
        _sauron_users.filter(
            eu_mask &
            (pl.col("last_auth_date") < cutoff) &
            (pl.col("is_anonymized") == False)
        ).height
    )
    active = eu_eea_total - anonymized - eligible

    # Last purge info
    last_run_date   = None
    last_run_purged = 0
    if _gdpr_log is not None and _gdpr_log.height > 0 and "run_date" in _gdpr_log.schema:
        last_row        = _gdpr_log.sort("run_date").tail(1)
        last_run_date   = last_row["run_date"][0]
        last_run_purged = int(last_row["newly_purged"][0])

    # Monthly history
    history: list[dict] = []
    if _gdpr_log is not None and _gdpr_log.height > 0 and "run_date" in _gdpr_log.schema:
        monthly = (
            _gdpr_log
            .with_columns(pl.col("run_date").str.slice(0, 7).alias("month"))
            .group_by("month")
            .agg(pl.sum("newly_purged").alias("purged"))
            .sort("month")
        )
        history = [{"month": r["month"], "purged": r["purged"]}
                   for r in monthly.to_dicts()]

    run_log: list[dict] = []
    if _gdpr_log is not None and _gdpr_log.height > 0 and "run_date" in _gdpr_log.schema:
        run_log = _gdpr_log.sort("run_date", descending=True).to_dicts()

    return {
        "total_users":      total,
        "eu_eea_scope":     eu_eea_total,
        "non_eu_total":     non_eu_total,
        "active_users":     active,
        "anonymized_total": anonymized,
        "pending_purge":    eligible,
        "retention_days":   365,
        "cutoff_date":      cutoff,
        "last_run_date":    last_run_date,
        "last_run_purged":  last_run_purged,
        "monthly_history":  history,
        "run_log":          run_log,
    }


@app.post("/api/gdpr/purge")
async def gdpr_manual_purge():
    """Manual trigger — runs purge immediately and returns summary."""
    try:
        result = _run_gdpr_purge()
        # Reload in-memory state so API reflects new state
        global _sauron_users, _gdpr_log
        _sauron_users = pl.read_parquet(DATA / "sauron_users.parquet")
        _gdpr_log     = pl.read_parquet(DATA / "gdpr_log.parquet") if (DATA / "gdpr_log.parquet").exists() else pl.DataFrame()
        return result
    except Exception as exc:
        raise HTTPException(500, f"Purge failed: {exc}")


# ── API: live snapshot (raw Rust DB state) ────────────────────────────────────
@app.get("/api/live")
def api_live():
    """
    Returns the exact live state from the Rust SQLite DB.
    This is the single source of truth for users, clients and token balances.
    Useful for debugging and for the partner portal cross-check.
    """
    live  = _fetch_rust_state()
    stats = live.get("stats", {})
    clients = live.get("clients", [])
    users   = live.get("users",   [])
    reqs    = live.get("requests", [])

    # Compute per-type aggregates
    full_kyc  = [c for c in clients if c.get("client_type") == "FULL_KYC"]
    zkp_only  = [c for c in clients if c.get("client_type") == "ZKP_ONLY"]
    total_a   = sum(c.get("tokens_a", 0) for c in clients)
    total_b   = sum(c.get("tokens_b", 0) for c in clients)

    return {
        "source":   "rust_sqlite_inmemory",
        "stats":    stats,
        "summary": {
            "total_clients":  len(clients),
            "full_kyc_count": len(full_kyc),
            "zkp_only_count": len(zkp_only),
            "total_users":    len(users),
            "total_tokens_a_in_circulation": total_a,
            "total_tokens_b_in_circulation": total_b,
            "recent_requests": len(reqs),
        },
        "clients": [
            {"name": c["name"], "type": c["client_type"],
             "tokens_a": c.get("tokens_a", 0), "tokens_b": c.get("tokens_b", 0)}
            for c in clients
        ],
        "users": [
            {"first_name": u["first_name"], "last_name": u["last_name"],
             "nationality": u["nationality"]}
            for u in users
        ],
        "recent_requests": reqs[:50],
    }


# ── Pipeline stats proxy ──────────────────────────────────────────────────────

@app.get("/api/pipeline-stats")
async def pipeline_stats():
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{INGEST_URL}/ingest/stats")
            return resp.json()
    except Exception:
        # Ingest server is not running — return honest empty state
        return {
            "live": False,
            "throughput": 0,
            "avg_latency_ms": 0,
            "uptime_pct": 0,
            "fraud_detected": 0,
            "total_events": 0,
            "latency": [],
            "resources": [],
        }


# ── Live fraud feed (proxy from ingest SSE) ───────────────────────────────────

@app.get("/api/fraud-stream")
async def fraud_stream(request: Request):
    """
    Proxy the ingest server's SSE stream to dashboard clients.
    If the ingest server is not running, the stream ends gracefully.
    """
    async def generator() -> AsyncIterator[str]:
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream("GET", f"{INGEST_URL}/ingest/stream") as resp:
                    async for line in resp.aiter_lines():
                        if await request.is_disconnected():
                            break
                        if line:
                            yield f"{line}\n"
                        else:
                            yield "\n"
        except Exception as exc:
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"

    return StreamingResponse(generator(), media_type="text/event-stream")


# ══════════════════════════════════════════════════════════════════════════════
#  Company Analytics endpoints (merged from analytics-dashboard)
# ══════════════════════════════════════════════════════════════════════════════

# ── Sauron backend proxy (for analytics JSON stored in Rust DB) ──────────────
def _fetch_sauron(data_type: str, company_id: int) -> dict:
    """Fetch analytics data from the Sauron Rust backend."""
    url = f"{SAURON_URL}/data/{data_type}/{company_id}"
    try:
        req = UrlRequest(url, method="GET")
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except UrlHTTPError as e:
        if e.code == 404:
            raise HTTPException(404, f"No {data_type} data for company {company_id}")
        raise HTTPException(502, f"Sauron backend error: {e.code}")
    except Exception as e:
        raise HTTPException(502, f"Cannot reach Sauron backend: {e}")


# ── CSV data cached at first load ─────────────────────────────────────────────
_companies_cache  : list[dict] | None = None
_trends_cache     : list[dict] | None = None
_personas_cache   : list[dict] | None = None


def _load_companies() -> list[dict]:
    global _companies_cache
    if _companies_cache is None:
        path = os.path.join(DATA_DIR, "companies.csv")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            _companies_cache = list(csv.DictReader(f))
    return _companies_cache


def _load_trends() -> list[dict]:
    global _trends_cache
    if _trends_cache is None:
        path = os.path.join(DATA_DIR, "company_trends.csv")
        if not os.path.exists(path):
            return []
        rows = []
        with open(path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                r["month"]               = int(r["month"])
                r["trend_index"]         = float(r["trend_index"])
                r["estimated_customers"] = int(r["estimated_customers"])
                rows.append(r)
        _trends_cache = rows
    return _trends_cache


def _load_personas() -> list[dict]:
    global _personas_cache
    if _personas_cache is None:
        path = os.path.join(DATA_DIR, "personas.csv")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            _personas_cache = list(csv.DictReader(f))
    return _personas_cache


def _persona_summary(rows: list[dict]) -> dict:
    categories = ["food_living", "tech", "lifestyle", "travel", "investment"]
    avg_spend  = {}
    for cat in categories:
        vals = [float(r[f"{cat}_usd"]) for r in rows if r.get(f"{cat}_usd")]
        avg_spend[cat] = round(sum(vals) / len(vals), 2) if vals else 0
    avg_net_worth = round(sum(float(r["net_worth_usd"]) for r in rows) / len(rows), 2) if rows else 0
    avg_income    = round(sum(float(r["monthly_income_usd"]) for r in rows) / len(rows), 2) if rows else 0
    return {
        "total":                 len(rows),
        "by_country":            dict(Counter(r["country"]           for r in rows)),
        "by_tier":               dict(Counter(r["wealth_tier"]        for r in rows)),
        "by_generation":         dict(Counter(r["generation"]         for r in rows)),
        "by_frequency":          dict(Counter(r["internet_frequency"] for r in rows)),
        "avg_monthly_spend_usd": avg_spend,
        "avg_net_worth_usd":     avg_net_worth,
        "avg_monthly_income_usd": avg_income,
    }


# ── Analytics HTML pages ──────────────────────────────────────────────────────
@app.get("/forecast", response_class=HTMLResponse)
def page_forecast():
    return _page("forecast.html")

@app.get("/fraud", response_class=HTMLResponse)
def page_fraud():
    return _page("fraud.html")


# ── Analytics Data APIs ──────────────────────────────────────────────────────
@app.get("/api/companies")
async def get_companies_csv():
    return _load_companies()

@app.get("/api/trends")
async def get_trends_csv():
    return _load_trends()

@app.get("/api/personas/summary")
async def get_personas_summary():
    return _persona_summary(_load_personas())

@app.get("/api/personas/by_category/{category}")
async def get_personas_by_category(category: str):
    if category not in VALID_CATEGORIES:
        raise HTTPException(400, f"Invalid category. Must be one of: {sorted(VALID_CATEGORIES)}")
    cats = list(VALID_CATEGORIES)
    def primary_cat(r: dict) -> str:
        return max(cats, key=lambda c: float(r.get(f"{c}_usd", 0)))
    filtered = [r for r in _load_personas() if primary_cat(r) == category]
    if not filtered:
        raise HTTPException(404, f"No personas found for category '{category}'")
    summary = _persona_summary(filtered)
    summary["category"] = category
    return summary

@app.get("/api/forecast/{company_id}")
async def get_forecast(company_id: int):
    if company_id <= 0:
        raise HTTPException(400, "company_id must be a positive integer")
    return _fetch_sauron("forecast", company_id)

@app.get("/api/fraud/summary/{company_id}")
async def get_fraud_summary(company_id: int):
    if company_id <= 0:
        raise HTTPException(400, "company_id must be a positive integer")
    return _fetch_sauron("fraud_summary", company_id)

@app.get("/api/fraud/recent/{company_id}")
async def get_fraud_recent(company_id: int):
    if company_id <= 0:
        raise HTTPException(400, "company_id must be a positive integer")
    return _fetch_sauron("fraud_recent", company_id)

@app.get("/api/stats/{company_id}")
async def get_company_stats(company_id: int):
    if company_id <= 0:
        raise HTTPException(400, "company_id must be a positive integer")
    return _fetch_sauron("stats", company_id)


# ─────────────────────────────────────────────────────────────────────────
# Live-only endpoints (Analytics 5/5).
#
# These bypass the parquet path entirely. Every byte returned here is read
# from the SauronID core in real time. When the core is unreachable, we
# return HTTP 503 with the failure mode in plain text — never stale data,
# never silently-stub data. The dashboard prefers these endpoints for any
# panel that must reflect the truth of the running system.
#
# Legacy `/api/overview`, `/api/insights/*`, etc. still exist for backwards
# compatibility and may use the parquet tier when present. Migrate panels
# to /api/live/* incrementally.
# ─────────────────────────────────────────────────────────────────────────

from fastapi import status as _http_status
import live_source as _live  # noqa: E402  (intentional bottom import)


def _live_handler(fn):
    """Decorator that maps LiveSourceError to a clean HTTP 503 with the
    diagnostic message, instead of a 500 stack trace."""
    from functools import wraps

    @wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except _live.LiveSourceError as exc:
            raise HTTPException(
                status_code=_http_status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "live source unreachable",
                    "hint": str(exc),
                    "doc": "https://github.com/your-org/sauronid/blob/main/docs/operations.md#health",
                },
            )

    return wrapper


@app.get("/api/live/health")
@_live_handler
async def live_health():
    return _live.fetch_health()


@app.get("/api/live/overview")
@_live_handler
async def live_overview():
    """Top-level overview shaped to match the dashboard's `OverviewData`.

    Includes:
      - kpis     : counts read from /admin/stats + /admin/agents
      - daily    : last-90-days bucketed counts from agent_action_receipts and api_usage
      - rings    : ring sizes (clients/users/agents) from /admin/stats.controls
      - anchor   : pending/upgraded/confirmed counts (extra, beyond legacy shape)
      - controls : compliance/issuer/risk/screening config
    """
    import time as _time
    from collections import Counter as _Counter

    stats = _live.fetch_stats()
    agents = _live.fetch_agents()
    anchor = _live.fetch_anchor_status()

    # Daily series: last 90 days, count of agent_action_receipts per day plus
    # api_usage rows from /admin/requests (the closest 'credit_b' analogue we
    # actually have in the live store).
    actions = _live.fetch_recent_actions(limit=1000)
    requests = _live.fetch_requests(limit=1000)

    today = int(_time.time()) // 86400
    days = list(range(today - 89, today + 1))
    by_day_actions = _Counter(int(a.get("created_at", 0)) // 86400 for a in actions)
    by_day_requests = _Counter(int(r.get("timestamp", 0)) // 86400 for r in requests)

    daily = {
        "dates":         [_time.strftime("%Y-%m-%d", _time.gmtime(d * 86400)) for d in days],
        "actions":       [by_day_actions.get(d, 0) for d in days],
        "api_requests":  [by_day_requests.get(d, 0) for d in days],
        # Backward-compat aliases for any older client; remove once nothing reads them.
        "credit_a":      [by_day_actions.get(d, 0) for d in days],
        "credit_b":      [by_day_requests.get(d, 0) for d in days],
    }

    # Ring sizes: surface what we actually have from live state.
    clients = _live.fetch_clients()
    users = _live.fetch_users()
    rings = {
        "labels": ["clients", "users", "agents"],
        "names": ["clients", "users", "agents"],
        "counts": [len(clients), len(users), len(agents)],
    }

    return {
        "kpis": {
            "total_users":          stats.get("total_users", 0),
            "total_clients":        stats.get("total_clients", 0),
            "total_agents":         len(agents),
            "active_agents":        sum(1 for a in agents if not a.get("revoked")),
            "total_api_calls":      stats.get("total_api_calls", 0),
            "total_kyc_retrievals": stats.get("total_kyc_retrievals", 0),
            "total_agent_calls":    stats.get("total_agent_calls", 0),
        },
        "daily":    daily,
        "rings":    rings,
        "anchor":   anchor,
        "controls": stats.get("controls", {}),
    }


@app.get("/api/live/agents")
@_live_handler
async def live_agents():
    """Every agent + checksum + revocation status. No parquet; no stale data."""
    return _live.fetch_agents()


@app.get("/api/live/agents/{agent_id}/checksum-history")
@_live_handler
async def live_agent_checksum_history(agent_id: str):
    return _live.fetch_checksum_audit(agent_id)


@app.get("/api/live/agent_actions/recent")
@_live_handler
async def live_recent_actions(limit: int = 200):
    return _live.fetch_recent_actions(min(max(1, limit), 1000))


@app.get("/api/live/egress/recent")
@_live_handler
async def live_recent_egress(limit: int = 200):
    return _live.fetch_recent_egress(min(max(1, limit), 1000))


@app.get("/api/live/per_agent_metrics")
@_live_handler
async def live_per_agent_metrics(limit: int = 50):
    return _live.fetch_per_agent_metrics(min(max(1, limit), 500))


@app.get("/api/live/anchor/status")
@_live_handler
async def live_anchor_status():
    return _live.fetch_anchor_status()


@app.get("/api/live/clients")
@_live_handler
async def live_clients():
    return _live.fetch_clients()


@app.get("/api/live/users")
@_live_handler
async def live_users():
    return _live.fetch_users()


@app.get("/api/live/requests")
@_live_handler
async def live_requests(limit: int = 200):
    return _live.fetch_requests(min(max(1, limit), 1000))


@app.get("/api/live/ping")
async def live_ping():
    """Liveness probe for the dashboard's 'core reachable' indicator."""
    try:
        _live.fetch_stats()
        return {"ok": True, "core_url": _live.SAURON_URL}
    except _live.LiveSourceError as exc:
        raise HTTPException(
            status_code=_http_status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"ok": False, "error": str(exc)},
        )


# ─── Interactive demo ──────────────────────────────────────────────────────
# /api/live/demo/run executes the full simulate_real_actions.py flow against
# the live core and returns a structured summary. The dashboard's /demo page
# calls this. The script is the source of truth for the agent-binding flow,
# so the demo is provably what production looks like.
# ──────────────────────────────────────────────────────────────────────────

import subprocess as _subprocess  # noqa: E402
import re as _re  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SIMULATE_SCRIPT = _REPO_ROOT / "scripts" / "simulate_real_actions.py"


def _parse_simulate_output(stdout: str) -> dict:
    """Pull structured info out of the script's print statements."""
    agent_id = None
    digest = None
    receipts: list[dict] = []
    anchor_id = None
    for line in stdout.splitlines():
        m = _re.search(r"agent_id=(agt_\w+)", line)
        if m:
            agent_id = m.group(1)
            continue
        m = _re.search(r"config_digest=(sha256:\w+)", line)
        if m:
            digest = m.group(1).rstrip("…")
            continue
        m = _re.search(r"receipt_id=(ar_\w+)", line)
        if m:
            receipts.append({"receipt_id": m.group(1)})
            continue
        m = _re.search(r"action_hash=(\w+)", line)
        if m and receipts:
            receipts[-1]["action_hash"] = m.group(1).rstrip("…")
            continue
        m = _re.search(r"anchor_id['\"]?:\s*['\"]?(aaa_\w+)", line)
        if m:
            anchor_id = m.group(1)
    return {
        "agent_id": agent_id,
        "config_digest": digest,
        "receipts": receipts,
        "anchor_id": anchor_id,
    }


_DEMO_ATTACKS = [
    "replay_jti", "tamper_body", "replay_nonce", "drift_digest", "forged_agent_id",
]


def _demo_subprocess_args(body: dict, *, stream: bool, attack: str | None = None) -> list[str]:
    """Build the simulate_real_actions.py argv for a given demo body."""
    args = ["python3", "-u", str(_SIMULATE_SCRIPT)]
    if attack:
        args += ["attack", attack]
    else:
        args += ["run"]
    if stream:
        args += ["--stream"]

    n_actions = max(1, min(int(body.get("n_actions") or 1), 5))
    args += ["--n-actions", str(n_actions)]
    args += ["--email", (body.get("email") or "alice@sauron.dev").strip()]
    args += ["--password", (body.get("password") or "pass_alice").strip()]

    # Optional intent overrides — only forwarded when set
    for key, flag in [
        ("model_id", "--model-id"),
        ("system_prompt", "--system-prompt"),
        ("tools", "--tools"),
        ("max_amount", "--max-amount"),
        ("currency", "--currency"),
        ("merchant_allowlist", "--merchant-allowlist"),
        ("intent_scope", "--intent-scope"),
    ]:
        v = body.get(key)
        if v in (None, "", []):
            continue
        if isinstance(v, list):
            v = ",".join(str(x) for x in v)
        args += [flag, str(v)]
    return args


def _demo_subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("SAURON_CORE_URL", _live.SAURON_URL)
    env.setdefault("SAURON_ADMIN_KEY", os.getenv("SAURON_ADMIN_KEY", ADMIN_KEY))
    env.setdefault(
        "SAURONID_AGENT_ACTION_TOOL",
        str(_REPO_ROOT / "core" / "target" / "release" / "agent-action-tool"),
    )
    return env


@app.post("/api/live/demo/stream")
async def live_demo_stream(req: Request):
    """Server-sent-events feed of one full demo run.

    Body: {n_actions, email, password, model_id?, system_prompt?, tools?,
           max_amount?, currency?, merchant_allowlist?}
    """
    try:
        body = await req.json()
    except Exception:
        body = {}

    if not _SIMULATE_SCRIPT.exists():
        raise HTTPException(status_code=500, detail=f"script missing: {_SIMULATE_SCRIPT}")

    cmd = _demo_subprocess_args(body, stream=True)
    env = _demo_subprocess_env()

    async def event_stream() -> AsyncIterator[str]:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=str(_REPO_ROOT),
        )
        assert proc.stdout is not None
        try:
            async for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
                if not line:
                    continue
                # Pass through as a single SSE message
                yield f"data: {line}\n\n"
        finally:
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        if proc.returncode and proc.returncode != 0:
            stderr = (await proc.stderr.read()).decode("utf-8", errors="replace")[-1500:] if proc.stderr else ""
            yield f"data: {json.dumps({'event': 'subprocess.exit', 'returncode': proc.returncode, 'stderr_tail': stderr})}\n\n"
        yield "event: end\ndata: {}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/live/demo/attack/{kind}")
async def live_demo_attack(kind: str, req: Request):
    """Provision a fresh agent then perform one negative test against it.

    Body: {email, password}
    Returns the same NDJSON events as `/api/live/demo/stream` would emit.
    """
    if kind not in _DEMO_ATTACKS:
        raise HTTPException(status_code=400, detail=f"unknown attack: {kind}")
    try:
        body = await req.json()
    except Exception:
        body = {}

    cmd = _demo_subprocess_args(body, stream=True, attack=kind)
    env = _demo_subprocess_env()

    async def event_stream() -> AsyncIterator[str]:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=str(_REPO_ROOT),
        )
        assert proc.stdout is not None
        try:
            async for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
                if not line:
                    continue
                yield f"data: {line}\n\n"
        finally:
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        yield "event: end\ndata: {}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/live/demo/attacks")
async def live_demo_attack_catalog():
    return {
        "attacks": [
            {"kind": "replay_jti",       "label": "Replay an A-JWT (jti single-use)",
             "expect": "second call rejected: A-JWT jti replay"},
            {"kind": "tamper_body",      "label": "Tamper request body after signing",
             "expect": "401 — call signature verification failed"},
            {"kind": "replay_nonce",     "label": "Reuse the same per-call nonce",
             "expect": "409 — call nonce replay"},
            {"kind": "drift_digest",     "label": "Drift x-sauron-agent-config-digest header",
             "expect": "401 — config drift"},
            {"kind": "forged_agent_id",  "label": "Sign with one agent's PoP, claim a different agent_id",
             "expect": "401 — config drift / PoP mismatch"},
            {"kind": "revocation",       "label": "Use an agent's A-JWT after revocation",
             "expect": "401 — Agent has been revoked"},
            {"kind": "delegation_escalation", "label": "Child agent claims scope outside parent intent",
             "expect": "400 — child scope must be subset of parent"},
        ]
    }


# ─── Multi-provider LLM call ───────────────────────────────────────────────
# /api/live/demo/llm-call accepts {provider, api_key, base_url?, model,
# system_prompt, user_message, tool_name, tool_schema}. It dispatches to the
# right provider format (Anthropic / OpenAI-compatible / Gemini), parses the
# tool-use response, and returns a normalised payload the dashboard can show.
# Providers covered:
#   anthropic       → api.anthropic.com /v1/messages
#   openai          → api.openai.com /v1/chat/completions  (also: Codex, others)
#   gemini          → generativelanguage.googleapis.com (functionDeclarations)
#   mistral         → api.mistral.ai (OpenAI-compatible)
#   deepseek        → api.deepseek.com (OpenAI-compatible)
#   qwen            → dashscope.aliyuncs.com (OpenAI-compatible mode)
#   groq            → api.groq.com (OpenAI-compatible)
#   together        → api.together.xyz (OpenAI-compatible)
#   openai-custom   → caller-supplied base_url, OpenAI-compatible schema

# Provider config — { id → {base_url, env_key, label, default_model, needs_base_url} }
# env_key: name of the .env variable that, if present, fills the API key
# automatically so the user doesn't have to paste it in the browser.
_LLM_PROVIDERS = {
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1/messages",
        "env_key":  "ANTHROPIC_API_KEY",
        "label":    "Anthropic Claude",
        "default_model": "claude-sonnet-4-5",
        "needs_base_url": False,
    },
    "openai": {
        "base_url": "https://api.openai.com/v1/chat/completions",
        "env_key":  "OPENAI_API_KEY",
        "label":    "OpenAI / Codex",
        "default_model": "gpt-4.1-mini",
        "needs_base_url": False,
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/models",
        "env_key":  "GEMINI_API_KEY",
        "label":    "Google Gemini",
        "default_model": "gemini-1.5-flash",
        "needs_base_url": False,
    },
    "mistral": {
        "base_url": "https://api.mistral.ai/v1/chat/completions",
        "env_key":  "MISTRAL_API_KEY",
        "label":    "Mistral",
        "default_model": "mistral-medium-latest",
        "needs_base_url": False,
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1/chat/completions",
        "env_key":  "DEEPSEEK_API_KEY",
        "label":    "DeepSeek",
        "default_model": "deepseek-chat",
        "needs_base_url": False,
    },
    "qwen": {
        "base_url": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions",
        "env_key":  "QWEN_API_KEY",
        "label":    "Qwen (DashScope)",
        "default_model": "qwen-plus",
        "needs_base_url": False,
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1/chat/completions",
        "env_key":  "GROQ_API_KEY",
        "label":    "Groq",
        "default_model": "llama-3.3-70b-versatile",
        "needs_base_url": False,
    },
    "together": {
        "base_url": "https://api.together.xyz/v1/chat/completions",
        "env_key":  "TOGETHER_API_KEY",
        "label":    "Together AI",
        "default_model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "needs_base_url": False,
    },
    "tavily": {
        "base_url": "https://api.tavily.com/search",
        "env_key":  "TAVILY_API_KEY",
        "label":    "Tavily Search",
        "default_model": "search",      # not a model — Tavily has one search service
        "needs_base_url": False,
    },
    "openai-custom": {
        "base_url": "",                  # caller supplies
        "env_key":  "OPENAI_CUSTOM_API_KEY",
        "label":    "Custom OpenAI-compatible",
        "default_model": "",
        "needs_base_url": True,
    },
}


@app.get("/api/live/demo/llm-providers")
async def live_demo_llm_providers():
    return {
        "providers": [
            {
                "id":             pid,
                "label":          spec["label"],
                "default_model":  spec["default_model"],
                "needs_base_url": spec["needs_base_url"],
                "env_key":        spec["env_key"],
                "has_env_key":    bool(os.getenv(spec["env_key"], "").strip()),
            }
            for pid, spec in _LLM_PROVIDERS.items()
        ]
    }


def _llm_call_tavily(api_key: str, query: str) -> dict:
    """Tavily isn't a chat model — it's a search-augmented retrieval API.
    Treated as 'one search per call'. Surfaces an answer + top results.
    """
    body = {
        "api_key":          api_key,
        "query":            query,
        "search_depth":     "basic",
        "include_answer":   True,
        "max_results":      5,
        "include_domains":  [],
    }
    r = httpx.post("https://api.tavily.com/search", json=body, timeout=60)
    r.raise_for_status()
    j = r.json()
    answer = j.get("answer") or ""
    results = j.get("results") or []
    # Synthesise a tool_call shape so the dashboard can render it identically.
    return {
        "provider": "tavily", "model": "tavily/search",
        "tool_call": {
            "name": "tavily_search",
            "args": {
                "query": query,
                "answer": answer,
                "top_results": [
                    {
                        "title": r.get("title", ""),
                        "url":   r.get("url", ""),
                        "score": r.get("score", 0.0),
                    }
                    for r in results
                ],
            },
        },
        "text":  answer,
        "usage": {"results": len(results)},
        "raw":   j,
    }


def _llm_call_anthropic(
    api_key: str, model: str, system_prompt: str,
    user_message: str, tool_name: str, tool_schema: dict,
) -> dict:
    body = {
        "model": model,
        "max_tokens": 1024,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_message}],
        "tools": [{
            "name": tool_name,
            "description": f"Execute the {tool_name} action through SauronID.",
            "input_schema": tool_schema,
        }],
    }
    r = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json=body, timeout=60,
    )
    r.raise_for_status()
    j = r.json()
    tool_use = next((c for c in (j.get("content") or []) if c.get("type") == "tool_use"), None)
    text = "".join(c.get("text", "") for c in (j.get("content") or []) if c.get("type") == "text")
    return {
        "provider": "anthropic", "model": model,
        "tool_call": tool_use and {"name": tool_use["name"], "args": tool_use["input"]},
        "text": text, "usage": j.get("usage"), "raw": j,
    }


def _llm_call_openai_compatible(
    base_url: str, api_key: str, model: str, system_prompt: str,
    user_message: str, tool_name: str, tool_schema: dict,
) -> dict:
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_message},
        ],
        "tools": [{
            "type": "function",
            "function": {
                "name": tool_name,
                "description": f"Execute the {tool_name} action through SauronID.",
                "parameters": tool_schema,
            },
        }],
        "tool_choice": "auto",
    }
    r = httpx.post(
        base_url,
        headers={"authorization": f"Bearer {api_key}", "content-type": "application/json"},
        json=body, timeout=60,
    )
    r.raise_for_status()
    j = r.json()
    msg = (j.get("choices") or [{}])[0].get("message") or {}
    tool_calls = msg.get("tool_calls") or []
    tool = tool_calls[0] if tool_calls else None
    args = None
    if tool:
        try:
            args = json.loads(tool["function"]["arguments"])
        except Exception:
            args = {"_raw": tool["function"].get("arguments")}
    return {
        "provider": "openai-compatible", "model": model,
        "tool_call": tool and {"name": tool["function"]["name"], "args": args},
        "text": msg.get("content"),
        "usage": j.get("usage"), "raw": j,
    }


def _llm_call_gemini(
    api_key: str, model: str, system_prompt: str,
    user_message: str, tool_name: str, tool_schema: dict,
) -> dict:
    base = "https://generativelanguage.googleapis.com/v1beta/models"
    url = f"{base}/{model}:generateContent?key={api_key}"
    body = {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_message}]}],
        "tools": [{
            "function_declarations": [{
                "name": tool_name,
                "description": f"Execute the {tool_name} action through SauronID.",
                "parameters": tool_schema,
            }],
        }],
        "tool_config": {"function_calling_config": {"mode": "AUTO"}},
    }
    r = httpx.post(url, json=body, timeout=60)
    r.raise_for_status()
    j = r.json()
    parts = (((j.get("candidates") or [{}])[0]).get("content") or {}).get("parts") or []
    fn = next((p for p in parts if p.get("functionCall")), None)
    text = "".join(p.get("text", "") for p in parts if "text" in p)
    return {
        "provider": "gemini", "model": model,
        "tool_call": fn and {"name": fn["functionCall"]["name"], "args": fn["functionCall"].get("args", {})},
        "text": text, "usage": j.get("usageMetadata"), "raw": j,
    }


@app.post("/api/live/demo/llm-call")
async def live_demo_llm_call(req: Request):
    """Call any LLM provider with a single tool definition; surface the tool_use.

    Body: {provider, api_key?, base_url?, model, system_prompt, user_message,
           tool_name, tool_schema}

    If api_key is empty, the server falls back to the env var named in the
    provider's `env_key` (e.g. ANTHROPIC_API_KEY). This lets you set keys in
    .env and never paste them in the browser.

    Returns: {provider, model, tool_call, text, usage, key_source}.
    """
    body = await req.json()
    provider = (body.get("provider") or "").strip()
    if not provider or provider not in _LLM_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"unknown provider: {provider!r}")

    spec = _LLM_PROVIDERS[provider]
    body_key = (body.get("api_key") or "").strip()
    env_key  = os.getenv(spec["env_key"], "").strip()
    api_key  = body_key or env_key
    key_source = "body" if body_key else ("env" if env_key else "")
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail=(
                f"no api_key supplied and {spec['env_key']} is not set in the "
                "environment. Either paste a key in the dashboard or add it to .env."
            ),
        )

    model = (body.get("model") or "").strip()
    system_prompt = body.get("system_prompt") or "You are a payment-initiating agent. When asked to pay, call the pay_merchant tool with the amount, currency and merchant_id."
    user_message = body.get("user_message") or "Send 15.00 EUR to mch_demo_payments for invoice INV-2026-001."
    tool_name = body.get("tool_name") or "pay_merchant"
    tool_schema = body.get("tool_schema") or {
        "type": "object",
        "properties": {
            "amount":      {"type": "number",  "description": "Amount in major units"},
            "currency":    {"type": "string",  "description": "ISO-4217 currency code (e.g. EUR)"},
            "merchant_id": {"type": "string",  "description": "Merchant identifier"},
            "memo":        {"type": "string",  "description": "Free-form memo / reference"},
        },
        "required": ["amount", "currency", "merchant_id"],
    }

    try:
        if provider == "tavily":
            res = _llm_call_tavily(api_key, user_message)
        elif provider == "anthropic":
            res = _llm_call_anthropic(api_key, model or spec["default_model"],
                                       system_prompt, user_message, tool_name, tool_schema)
        elif provider == "gemini":
            res = _llm_call_gemini(api_key, model or spec["default_model"],
                                    system_prompt, user_message, tool_name, tool_schema)
        elif provider == "openai-custom":
            base = (body.get("base_url") or "").strip()
            if not base:
                raise HTTPException(status_code=400, detail="base_url required for openai-custom")
            res = _llm_call_openai_compatible(base, api_key, model,
                                               system_prompt, user_message, tool_name, tool_schema)
        else:
            base = spec["base_url"]
            res = _llm_call_openai_compatible(base, api_key, model or spec["default_model"],
                                               system_prompt, user_message, tool_name, tool_schema)
        res["key_source"] = key_source
        return res
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502,
            detail={"error": "upstream LLM error",
                    "status": e.response.status_code,
                    "body": e.response.text[:500],
                    "key_source": key_source},
        )
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"upstream LLM unreachable: {e}")


@app.post("/api/live/demo/llm-then-bind")
async def live_demo_llm_then_bind(req: Request):
    """Two-stage stream: call an LLM, then run the binding flow with the
    arguments the model proposed in its tool call.

    Body: {provider, api_key?, base_url?, model, user_message,
           email, password, tool_name?, tool_schema?}
    Streams: llm.start -> llm.done with parsed tool_call -> standard
    binding events (step.start/step.done/run.done) using the LLM args
    as intent overrides. If the LLM produces no tool_call OR the call
    fails, emits llm.fail and stops without running the binding (so the
    caller can fall back to the simple /demo/stream flow).
    """
    body = await req.json()
    provider = (body.get("provider") or "").strip()
    if not provider or provider not in _LLM_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"unknown provider: {provider!r}")

    spec = _LLM_PROVIDERS[provider]
    body_key = (body.get("api_key") or "").strip()
    env_key  = os.getenv(spec["env_key"], "").strip()
    api_key  = body_key or env_key
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail=f"no api_key supplied and {spec['env_key']} not set in env",
        )

    user_message = (body.get("user_message")
                    or "Send 15.00 EUR to mch_demo_payments for invoice INV-2026-001.")
    model = (body.get("model") or spec["default_model"]).strip()

    async def event_stream() -> AsyncIterator[str]:
        # ── 1. LLM call ────────────────────────────────────────────────
        yield f"data: {json.dumps({'event': 'llm.start', 'provider': provider, 'model': model})}\n\n"
        try:
            if provider == "tavily":
                # Tavily's "tool call" is a search shape; can't bind a search
                # to payment_authorize. Fall through with an explicit note.
                yield f"data: {json.dumps({'event': 'llm.fail', 'reason': 'tavily search results cannot drive payment_authorize binding — pick an LLM provider for the chained demo'})}\n\n"
                return
            elif provider == "anthropic":
                res = _llm_call_anthropic(
                    api_key, model,
                    body.get("system_prompt") or "You are a payment-initiating agent. Call pay_merchant with amount, currency and merchant_id.",
                    user_message,
                    body.get("tool_name") or "pay_merchant",
                    body.get("tool_schema") or {
                        "type": "object",
                        "properties": {
                            "amount":      {"type": "number"},
                            "currency":    {"type": "string"},
                            "merchant_id": {"type": "string"},
                            "memo":        {"type": "string"},
                        },
                        "required": ["amount", "currency", "merchant_id"],
                    },
                )
            elif provider == "gemini":
                res = _llm_call_gemini(
                    api_key, model,
                    body.get("system_prompt") or "You are a payment-initiating agent. Call pay_merchant with amount, currency and merchant_id.",
                    user_message,
                    body.get("tool_name") or "pay_merchant",
                    body.get("tool_schema") or {
                        "type": "object",
                        "properties": {
                            "amount":      {"type": "number"},
                            "currency":    {"type": "string"},
                            "merchant_id": {"type": "string"},
                            "memo":        {"type": "string"},
                        },
                        "required": ["amount", "currency", "merchant_id"],
                    },
                )
            elif provider == "openai-custom":
                base = (body.get("base_url") or "").strip()
                if not base:
                    yield f"data: {json.dumps({'event': 'llm.fail', 'reason': 'base_url required for openai-custom'})}\n\n"
                    return
                res = _llm_call_openai_compatible(
                    base, api_key, model,
                    body.get("system_prompt") or "You are a payment-initiating agent. Call pay_merchant with amount, currency and merchant_id.",
                    user_message,
                    body.get("tool_name") or "pay_merchant",
                    body.get("tool_schema") or {
                        "type": "object",
                        "properties": {
                            "amount":      {"type": "number"},
                            "currency":    {"type": "string"},
                            "merchant_id": {"type": "string"},
                            "memo":        {"type": "string"},
                        },
                        "required": ["amount", "currency", "merchant_id"],
                    },
                )
            else:
                base = spec["base_url"]
                res = _llm_call_openai_compatible(
                    base, api_key, model,
                    body.get("system_prompt") or "You are a payment-initiating agent. Call pay_merchant with amount, currency and merchant_id.",
                    user_message,
                    body.get("tool_name") or "pay_merchant",
                    body.get("tool_schema") or {
                        "type": "object",
                        "properties": {
                            "amount":      {"type": "number"},
                            "currency":    {"type": "string"},
                            "merchant_id": {"type": "string"},
                            "memo":        {"type": "string"},
                        },
                        "required": ["amount", "currency", "merchant_id"],
                    },
                )
        except Exception as e:
            yield f"data: {json.dumps({'event': 'llm.fail', 'reason': f'LLM call failed: {e}'})}\n\n"
            return

        tool_call = res.get("tool_call")
        yield f"data: {json.dumps({'event': 'llm.done', 'tool_call': tool_call, 'text': res.get('text'), 'usage': res.get('usage')})}\n\n"

        if not tool_call or not isinstance(tool_call.get("args"), dict):
            yield f"data: {json.dumps({'event': 'llm.fail', 'reason': 'model returned no structured tool call'})}\n\n"
            return

        args = tool_call["args"]
        amount = args.get("amount")
        currency = (args.get("currency") or "EUR").upper()
        merchant_id = args.get("merchant_id") or "mch_demo_payments"
        if not isinstance(amount, (int, float)) or amount <= 0:
            yield f"data: {json.dumps({'event': 'llm.fail', 'reason': 'tool call missing valid amount'})}\n\n"
            return

        # ── 2. Binding flow with LLM-derived intent ────────────────────
        binding_body = dict(body)
        binding_body.update({
            "n_actions": 1,
            "max_amount": f"{float(amount):.2f}",
            "currency":   currency,
            "merchant_allowlist": merchant_id,
            "intent_scope": "payment_initiation",
        })
        cmd = _demo_subprocess_args(binding_body, stream=True)
        env = _demo_subprocess_env()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=str(_REPO_ROOT),
        )
        assert proc.stdout is not None
        try:
            async for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
                if not line:
                    continue
                yield f"data: {line}\n\n"
        finally:
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        yield "event: end\ndata: {}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/live/demo/run")
async def live_demo_run(req: Request):
    """Run the full agent-binding flow end-to-end. Body: {n_actions, email, password}."""
    try:
        body = await req.json()
    except Exception:
        body = {}
    n_actions = max(1, min(int(body.get("n_actions", 1) or 1), 5))
    email = (body.get("email") or "alice@sauron.dev").strip()
    password = (body.get("password") or "pass_alice").strip()

    if not _SIMULATE_SCRIPT.exists():
        raise HTTPException(status_code=500, detail=f"script missing: {_SIMULATE_SCRIPT}")

    cmd = [
        "python3", str(_SIMULATE_SCRIPT),
        "--n-actions", str(n_actions),
        "--email", email,
        "--password", password,
    ]
    env = os.environ.copy()
    env.setdefault("SAURON_CORE_URL", _live.SAURON_URL)
    env.setdefault("SAURON_ADMIN_KEY", os.getenv("SAURON_ADMIN_KEY", ADMIN_KEY))
    env.setdefault(
        "SAURONID_AGENT_ACTION_TOOL",
        str(_REPO_ROOT / "core" / "target" / "release" / "agent-action-tool"),
    )

    try:
        proc = _subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, env=env, cwd=str(_REPO_ROOT)
        )
    except _subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="demo script timeout (>120s)")

    if proc.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail={
                "ok": False,
                "error": "simulate_real_actions.py exited non-zero",
                "stderr": proc.stderr[-2000:],
                "stdout_tail": proc.stdout[-2000:],
            },
        )

    parsed = _parse_simulate_output(proc.stdout)
    anchor = _live.fetch_anchor_status()
    return {
        "ok": True,
        "n_actions_requested": n_actions,
        "user": email,
        **parsed,
        "anchor_status": anchor,
        "stdout": proc.stdout,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8002, reload=False)

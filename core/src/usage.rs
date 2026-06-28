//! Phase 4 of the anonymous ring-policy redesign: multi-unit usage ledger.
//! See `docs/design/anonymous-ring-policy.md`.
//!
//! Tracks **tokens and money** per ring pseudonym (the per-ring key image), not
//! per agent identity — so accounting works under the anonymous model. Tokens
//! are authoritative; `usd` is derived from a per-model price map at record
//! time, which makes it provider-agnostic: online providers report usage,
//! local runtimes (vLLM / llama.cpp / Ollama) report counts, and a model with
//! no price entry simply has `usd = 0` while its tokens are still tracked.
//!
//! Budgets in `RingRule.budgets` are enforced per-pseudonym against the ledger
//! (see `agent_action::validate_anon_action`).
//!
//! Honesty boundary: token counts are host/gateway-reported (same class as the
//! config digest). The ledger + append-only `usage_log` make them tamper-evident
//! and anchorable; they become authoritative only when an in-path inference
//! gateway counts them (see `docs/ideas/blackbox-encrypted-inference.md`).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
};
use rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::rings::RingBudgets;
use crate::state::ServerState;

/// Per-model price, USD per 1,000 tokens.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ModelPrice {
    #[serde(default)]
    pub in_per_1k: f64,
    #[serde(default)]
    pub out_per_1k: f64,
}

/// Running totals for one ring pseudonym.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UsageTotals {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub usd: f64,
}

/// Load the per-model price map from `SAURON_MODEL_PRICES` (JSON object of
/// `model_id -> {in_per_1k, out_per_1k}`). Empty when unset/invalid.
fn load_price_map() -> HashMap<String, ModelPrice> {
    std::env::var("SAURON_MODEL_PRICES")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Pure money derivation from a price map. Unknown model → 0 (tokens still
/// tracked). Kept separate from env loading so it is unit-testable.
pub fn usd_from_prices(
    prices: &HashMap<String, ModelPrice>,
    model_id: &str,
    in_tokens: i64,
    out_tokens: i64,
) -> f64 {
    match prices.get(model_id) {
        Some(p) => {
            (in_tokens as f64 / 1000.0) * p.in_per_1k + (out_tokens as f64 / 1000.0) * p.out_per_1k
        }
        None => 0.0,
    }
}

/// Derive USD for a usage event using the env-configured price map.
pub fn derive_usd(model_id: &str, in_tokens: i64, out_tokens: i64) -> f64 {
    usd_from_prices(&load_price_map(), model_id, in_tokens, out_tokens)
}

/// Current lifetime totals for a ring pseudonym (zero when none recorded yet).
pub fn get_usage(
    db: &Connection,
    tenant_id: &str,
    ring_id: &str,
    key_image_hex: &str,
) -> Result<UsageTotals, String> {
    let row = db
        .query_row(
            "SELECT input_tokens, output_tokens, usd FROM usage_ledger
             WHERE tenant_id = ?1 AND ring_id = ?2 AND key_image_hex = ?3",
            params![tenant_id, ring_id, key_image_hex],
            |r| {
                Ok(UsageTotals {
                    input_tokens: r.get(0)?,
                    output_tokens: r.get(1)?,
                    usd: r.get(2)?,
                })
            },
        )
        .ok();
    Ok(row.unwrap_or_default())
}

/// Returns `Some(reason)` if the totals already exceed any budget the ring caps.
/// `None` budgets are unlimited.
pub fn budget_exceeded(totals: &UsageTotals, budgets: &RingBudgets) -> Option<String> {
    if let Some(cap) = budgets.usd {
        if totals.usd > cap {
            return Some(format!("usd {:.4} > cap {:.4}", totals.usd, cap));
        }
    }
    if let Some(cap) = budgets.input_tokens {
        if totals.input_tokens > cap {
            return Some(format!("input_tokens {} > cap {}", totals.input_tokens, cap));
        }
    }
    if let Some(cap) = budgets.output_tokens {
        if totals.output_tokens > cap {
            return Some(format!("output_tokens {} > cap {}", totals.output_tokens, cap));
        }
    }
    None
}

/// Record a usage event against the ring pseudonym that owns a receipt. Appends
/// to `usage_log` and atomically accumulates `usage_ledger`. Returns the new
/// totals. Requires an anon-ring receipt (legacy receipts have no `ring_id`).
pub fn record_usage(
    db: &Connection,
    receipt_id: &str,
    model_id: &str,
    in_tokens: i64,
    out_tokens: i64,
    now: i64,
) -> Result<(String, String, UsageTotals), (StatusCode, String)> {
    if in_tokens < 0 || out_tokens < 0 {
        return Err((StatusCode::BAD_REQUEST, "token counts must be >= 0".into()));
    }
    let (tenant_id, ring_id_opt, key_image): (String, Option<String>, String) = db
        .query_row(
            "SELECT tenant_id, ring_id, ring_key_image_hex FROM agent_action_receipts
             WHERE receipt_id = ?1",
            params![receipt_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "receipt not found".into()))?;
    let ring_id = ring_id_opt.filter(|s| !s.is_empty()).ok_or((
        StatusCode::BAD_REQUEST,
        "usage recording requires an anon-ring receipt (ring_id missing)".to_string(),
    ))?;

    let usd = derive_usd(model_id, in_tokens, out_tokens);
    let log_id = format!("ul_{}", crate::ajwt_support::random_hex_32());
    db.execute(
        "INSERT INTO usage_log
         (log_id, tenant_id, ring_id, key_image_hex, model_id, input_tokens, output_tokens, usd, recorded_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![log_id, tenant_id, ring_id, key_image, model_id, in_tokens, out_tokens, usd, now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    db.execute(
        "INSERT INTO usage_ledger
         (tenant_id, ring_id, key_image_hex, input_tokens, output_tokens, usd, updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(tenant_id, ring_id, key_image_hex) DO UPDATE SET
            input_tokens  = usage_ledger.input_tokens  + excluded.input_tokens,
            output_tokens = usage_ledger.output_tokens + excluded.output_tokens,
            usd           = usage_ledger.usd           + excluded.usd,
            updated_at    = excluded.updated_at",
        params![tenant_id, ring_id, key_image, in_tokens, out_tokens, usd, now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let totals = get_usage(db, &tenant_id, &ring_id, &key_image)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok((ring_id, key_image, totals))
}

/// Per-pseudonym totals for a whole ring (operator view).
pub fn list_ring_usage(
    db: &Connection,
    tenant_id: &str,
    ring_id: &str,
) -> Result<Vec<(String, UsageTotals)>, String> {
    let mut stmt = db
        .prepare(
            "SELECT key_image_hex, input_tokens, output_tokens, usd FROM usage_ledger
             WHERE tenant_id = ?1 AND ring_id = ?2 ORDER BY key_image_hex",
        )
        .map_err(|e| format!("prepare list_ring_usage: {e}"))?;
    let rows = stmt
        .query_map(params![tenant_id, ring_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                UsageTotals {
                    input_tokens: r.get(1)?,
                    output_tokens: r.get(2)?,
                    usd: r.get(3)?,
                },
            ))
        })
        .map_err(|e| format!("query list_ring_usage: {e}"))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| format!("row list_ring_usage: {e}"))?);
    }
    Ok(out)
}

// ─── HTTP handlers ───────────────────────────────────────────────────────────

fn default_tenant() -> String {
    "default".to_string()
}

#[derive(Deserialize)]
pub struct RecordUsageRequest {
    pub receipt_id: String,
    #[serde(default)]
    pub model_id: String,
    #[serde(default)]
    pub input_tokens: i64,
    #[serde(default)]
    pub output_tokens: i64,
}

#[derive(Deserialize)]
pub struct TenantQuery {
    #[serde(default = "default_tenant")]
    pub tenant_id: String,
}

/// POST /agent/usage — report token usage for a prior anon action receipt.
pub async fn record_usage_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(req): Json<RecordUsageRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if !crate::rings::anon_rings_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "anonymous rings are disabled (set SAURON_ANON_RINGS=1)".into(),
        ));
    }
    let now = crate::agent_action::now_secs();
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let (ring_id, key_image, totals) = record_usage(
        &db,
        &req.receipt_id,
        &req.model_id,
        req.input_tokens,
        req.output_tokens,
        now,
    )?;
    Ok(Json(json!({
        "ring_id": ring_id,
        "key_image_hex": key_image,
        "input_tokens": totals.input_tokens,
        "output_tokens": totals.output_tokens,
        "usd": totals.usd,
    })))
}

/// GET /admin/rings/{ring_id}/usage?tenant_id= — per-pseudonym usage totals.
pub async fn ring_usage_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(ring_id): Path<String>,
    Query(q): Query<TenantQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if !crate::rings::anon_rings_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "anonymous rings are disabled (set SAURON_ANON_RINGS=1)".into(),
        ));
    }
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let rows =
        list_ring_usage(&db, &q.tenant_id, &ring_id).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|(ki, t)| {
            json!({ "key_image_hex": ki, "input_tokens": t.input_tokens, "output_tokens": t.output_tokens, "usd": t.usd })
        })
        .collect();
    Ok(Json(json!({ "ring_id": ring_id, "pseudonyms": out })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_schema(&conn);
        conn
    }

    fn insert_anon_receipt(db: &Connection, receipt_id: &str, ring_id: Option<&str>, key_image: &str) {
        db.execute(
            "INSERT INTO agent_action_receipts
             (receipt_id, action_hash, agent_id, ring_key_image_hex, policy_version, ajwt_jti, pop_jkt, status, signature, created_at, ring_id, config_digest, tenant_id)
             VALUES (?1,'ah','',?2,'ring:r:v1','','','verified','sig',1,?3,'',?4)",
            params![receipt_id, key_image, ring_id, "default"],
        )
        .unwrap();
    }

    #[test]
    fn usd_derivation_uses_price_map_and_zero_for_unknown() {
        let mut prices = HashMap::new();
        prices.insert(
            "claude-opus-4-8".to_string(),
            ModelPrice { in_per_1k: 0.015, out_per_1k: 0.075 },
        );
        // 2000 in, 1000 out → 2*0.015 + 1*0.075 = 0.105
        let usd = usd_from_prices(&prices, "claude-opus-4-8", 2000, 1000);
        assert!((usd - 0.105).abs() < 1e-9, "got {usd}");
        // Local / unknown model → tokens tracked elsewhere, usd 0.
        assert_eq!(usd_from_prices(&prices, "local-llama", 9999, 9999), 0.0);
    }

    #[test]
    fn budget_exceeded_respects_caps_and_unlimited() {
        let totals = UsageTotals { input_tokens: 1500, output_tokens: 10, usd: 2.0 };
        // Unlimited everywhere.
        assert!(budget_exceeded(&totals, &RingBudgets::default()).is_none());
        // Under all caps.
        assert!(budget_exceeded(
            &totals,
            &RingBudgets { usd: Some(5.0), input_tokens: Some(2000), output_tokens: Some(100) }
        )
        .is_none());
        // Over the token cap.
        assert!(budget_exceeded(
            &totals,
            &RingBudgets { usd: None, input_tokens: Some(1000), output_tokens: None }
        )
        .is_some());
    }

    #[test]
    fn record_usage_accumulates_and_keys_on_pseudonym() {
        let db = mem_db();
        insert_anon_receipt(&db, "ar_1", Some("ring:r"), "kimg_abc");
        let (ring_id, ki, t1) = record_usage(&db, "ar_1", "local-model", 100, 50, 1).unwrap();
        assert_eq!(ring_id, "ring:r");
        assert_eq!(ki, "kimg_abc");
        assert_eq!(t1, UsageTotals { input_tokens: 100, output_tokens: 50, usd: 0.0 });
        // Second event accumulates on the same pseudonym.
        let (_, _, t2) = record_usage(&db, "ar_1", "local-model", 10, 5, 2).unwrap();
        assert_eq!(t2, UsageTotals { input_tokens: 110, output_tokens: 55, usd: 0.0 });
        assert_eq!(get_usage(&db, "default", "ring:r", "kimg_abc").unwrap(), t2);
    }

    #[test]
    fn record_usage_rejects_legacy_receipt_and_unknown_receipt() {
        let db = mem_db();
        // Legacy receipt: ring_id NULL.
        insert_anon_receipt(&db, "ar_legacy", None, "ki");
        let err = record_usage(&db, "ar_legacy", "m", 1, 1, 1).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        // Unknown receipt.
        let err = record_usage(&db, "ar_missing", "m", 1, 1, 1).unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }
}

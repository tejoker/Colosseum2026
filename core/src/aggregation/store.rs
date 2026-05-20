//! Sprint 7 — DB-backed `customer_stats` store.
//!
//! Idempotent upsert keyed on `(tenant_id, COALESCE(agent_id,''), metric_id,
//! period_start)`. Same submission landing twice — whether due to a network
//! retry or a scheduler restart — overwrites the previous row instead of
//! producing a duplicate. This mirrors how the spend ledger handles its
//! `(policy_id, agent_id, period_start)` key.

use rusqlite::{params, OptionalExtension};

use crate::aggregation::submission::{CohortRow, StatsSubmission};
use crate::aggregation::verify::AggError;
use crate::db::DbHandle;

/// Insert-or-update a single stats submission. Returns the now-current row.
pub fn upsert_submission(
    db: &DbHandle,
    sub: &StatsSubmission,
    submitted_at: i64,
) -> Result<CohortRow, AggError> {
    let conn = db.lock().map_err(|e| AggError::Storage(e.to_string()))?;
    let agent_key = sub.agent_id_or_none.clone().unwrap_or_default();
    conn.execute(
        r#"INSERT INTO customer_stats
           (tenant_id, agent_id, metric_id, claimed_value, n_records,
            period_start, period_end, merkle_root, proof_b64, vk_id, submitted_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
           ON CONFLICT (tenant_id, agent_id, metric_id, period_start)
           DO UPDATE SET
             claimed_value = excluded.claimed_value,
             n_records     = excluded.n_records,
             period_end    = excluded.period_end,
             merkle_root   = excluded.merkle_root,
             proof_b64     = excluded.proof_b64,
             vk_id         = excluded.vk_id,
             submitted_at  = excluded.submitted_at"#,
        params![
            sub.tenant_id,
            agent_key,
            sub.metric_id,
            sub.claimed_value,
            sub.n_records,
            sub.period_start,
            sub.period_end,
            sub.merkle_root,
            sub.proof_b64,
            sub.vk_id,
            submitted_at,
        ],
    )
    .map_err(|e| AggError::Storage(e.to_string()))?;

    Ok(CohortRow {
        tenant_id: sub.tenant_id.clone(),
        agent_id_or_none: sub.agent_id_or_none.clone(),
        metric_id: sub.metric_id.clone(),
        claimed_value: sub.claimed_value,
        n_records: sub.n_records,
        period_start: sub.period_start,
        period_end: sub.period_end,
        merkle_root: sub.merkle_root.clone(),
        submitted_at,
    })
}

/// List submissions for one `(metric_id, period)` window. Used by the
/// operator-facing `/v1/stats/cohort` endpoint. NOT the DP-published view.
pub fn list_cohort(
    db: &DbHandle,
    metric_id: &str,
    period_start: i64,
    period_end: i64,
) -> Result<Vec<CohortRow>, AggError> {
    let conn = db.lock().map_err(|e| AggError::Storage(e.to_string()))?;
    let mut stmt = conn
        .prepare(
            r#"SELECT tenant_id, agent_id, metric_id, claimed_value, n_records,
                      period_start, period_end, merkle_root, submitted_at
               FROM customer_stats
               WHERE metric_id = ?1
                 AND period_start = ?2
                 AND period_end   = ?3
               ORDER BY tenant_id ASC, agent_id ASC"#,
        )
        .map_err(|e| AggError::Storage(e.to_string()))?;
    let rows = stmt
        .query_map(params![metric_id, period_start, period_end], |r| {
            let agent_id: String = r.get(1)?;
            Ok(CohortRow {
                tenant_id: r.get(0)?,
                agent_id_or_none: if agent_id.is_empty() {
                    None
                } else {
                    Some(agent_id)
                },
                metric_id: r.get(2)?,
                claimed_value: r.get(3)?,
                n_records: r.get(4)?,
                period_start: r.get(5)?,
                period_end: r.get(6)?,
                merkle_root: r.get(7)?,
                submitted_at: r.get(8)?,
            })
        })
        .map_err(|e| AggError::Storage(e.to_string()))?;
    Ok(rows.flatten().collect())
}

/// List every submission whose tenant is in `tenant_ids` and whose period
/// is contained in `[period_start, period_end]`. Used by the Sprint 8
/// DP-publish pipeline — see `aggregation::publish::publish_cohort`.
///
/// Empty `tenant_ids` returns an empty Vec (no SQL roundtrip).
pub fn list_for_cohort(
    db: &DbHandle,
    tenant_ids: &[String],
    period_start: i64,
    period_end: i64,
) -> Result<Vec<CohortRow>, AggError> {
    if tenant_ids.is_empty() {
        return Ok(Vec::new());
    }
    let conn = db.lock().map_err(|e| AggError::Storage(e.to_string()))?;
    // Build a parameterised `IN (...)` clause. SQLite has a 999-param
    // ceiling by default — cap defensively and rely on the operator to
    // size cohorts within it (S8 ships ≤ a few hundred tenants).
    let placeholders: Vec<String> = (1..=tenant_ids.len()).map(|i| format!("?{i}")).collect();
    let sql = format!(
        "SELECT tenant_id, agent_id, metric_id, claimed_value, n_records,
                period_start, period_end, merkle_root, submitted_at
         FROM customer_stats
         WHERE tenant_id IN ({})
           AND period_start >= ?{}
           AND period_end   <= ?{}
         ORDER BY tenant_id ASC, metric_id ASC, submitted_at ASC",
        placeholders.join(","),
        tenant_ids.len() + 1,
        tenant_ids.len() + 2,
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| AggError::Storage(e.to_string()))?;
    let mut bound: Vec<&dyn rusqlite::ToSql> = tenant_ids
        .iter()
        .map(|s| s as &dyn rusqlite::ToSql)
        .collect();
    bound.push(&period_start);
    bound.push(&period_end);
    let rows = stmt
        .query_map(rusqlite::params_from_iter(bound.iter()), |r| {
            let agent_id: String = r.get(1)?;
            Ok(CohortRow {
                tenant_id: r.get(0)?,
                agent_id_or_none: if agent_id.is_empty() {
                    None
                } else {
                    Some(agent_id)
                },
                metric_id: r.get(2)?,
                claimed_value: r.get(3)?,
                n_records: r.get(4)?,
                period_start: r.get(5)?,
                period_end: r.get(6)?,
                merkle_root: r.get(7)?,
                submitted_at: r.get(8)?,
            })
        })
        .map_err(|e| AggError::Storage(e.to_string()))?;
    Ok(rows.flatten().collect())
}

/// Fetch a single submission by primary key. Returns `None` when not present.
pub fn get_one(
    db: &DbHandle,
    tenant_id: &str,
    agent_id_or_none: Option<&str>,
    metric_id: &str,
    period_start: i64,
) -> Result<Option<CohortRow>, AggError> {
    let conn = db.lock().map_err(|e| AggError::Storage(e.to_string()))?;
    let agent_key = agent_id_or_none.unwrap_or("");
    conn.query_row(
        r#"SELECT tenant_id, agent_id, metric_id, claimed_value, n_records,
                  period_start, period_end, merkle_root, submitted_at
           FROM customer_stats
           WHERE tenant_id = ?1
             AND agent_id  = ?2
             AND metric_id = ?3
             AND period_start = ?4"#,
        params![tenant_id, agent_key, metric_id, period_start],
        |r| {
            let agent_id: String = r.get(1)?;
            Ok(CohortRow {
                tenant_id: r.get(0)?,
                agent_id_or_none: if agent_id.is_empty() {
                    None
                } else {
                    Some(agent_id)
                },
                metric_id: r.get(2)?,
                claimed_value: r.get(3)?,
                n_records: r.get(4)?,
                period_start: r.get(5)?,
                period_end: r.get(6)?,
                merkle_root: r.get(7)?,
                submitted_at: r.get(8)?,
            })
        },
    )
    .optional()
    .map_err(|e| AggError::Storage(e.to_string()))
}

/// Synthetic action hash used to anchor a stats submission into the existing
/// agent-action merkle batch flow. By computing it as
/// `SHA256("stats_submission:" + merkle_root + ":" + metric_id)` we get:
///   1. A 32-byte hex string that fits the `agent_action_receipts.action_hash`
///      column.
///   2. Deterministic — re-running the upsert produces the same hash and the
///      audit chain sees one row per (root, metric_id) pair.
///   3. Distinct namespace from real action hashes (the prefix prevents
///      collisions with any agent's real `action_hash`).
pub fn synthetic_action_hash(merkle_root: &str, metric_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"stats_submission:");
    h.update(merkle_root.as_bytes());
    h.update(b":");
    h.update(metric_id.as_bytes());
    hex::encode(h.finalize())
}

/// Bind a stats submission into the existing audit chain by writing a row
/// into `agent_action_receipts`. The merkle anchor task picks the row up
/// and rolls it into the next OTS+Solana batch.
pub fn anchor_submission(
    db: &DbHandle,
    sub: &StatsSubmission,
    submitted_at: i64,
) -> Result<String, AggError> {
    let conn = db.lock().map_err(|e| AggError::Storage(e.to_string()))?;
    let action_hash = synthetic_action_hash(&sub.merkle_root, &sub.metric_id);
    let receipt_id = format!("stats_{}", &action_hash[..16]);
    // Synthetic agent_id encodes the tenant_id and optional real agent so
    // operators can filter the chain by tenant. Keep under 255 chars.
    let synthetic_agent_id = match &sub.agent_id_or_none {
        Some(a) => format!("__stats__:{}:{}", sub.tenant_id, a),
        None => format!("__stats__:{}", sub.tenant_id),
    };
    conn.execute(
        r#"INSERT OR IGNORE INTO agent_action_receipts
           (receipt_id, action_hash, agent_id, ring_key_image_hex,
            policy_version, ajwt_jti, pop_jkt, status, signature, created_at, tenant_id)
           VALUES (?1, ?2, ?3, '', 'stats-v1', ?2, '', 'stats_submitted', '', ?4, ?5)"#,
        params![
            receipt_id,
            action_hash,
            synthetic_agent_id,
            submitted_at,
            sub.tenant_id,
        ],
    )
    .map_err(|e| AggError::Storage(e.to_string()))?;
    Ok(action_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_db_at;

    fn temp_db(label: &str) -> DbHandle {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path = std::env::temp_dir()
            .join(format!("sauron-stats-{pid}-{nanos}-{label}.db"));
        let _ = std::fs::remove_file(&path);
        open_db_at(path.to_str().unwrap(), 2)
    }

    fn sample(tenant: &str, agent: Option<&str>) -> StatsSubmission {
        StatsSubmission {
            tenant_id: tenant.to_string(),
            agent_id_or_none: agent.map(|s| s.to_string()),
            metric_id: "success_rate".into(),
            claimed_value: 950,
            n_records: 100,
            period_start: 0,
            period_end: 60,
            merkle_root: "ab".repeat(32),
            proof_b64: "e30=".into(),
            vk_id: "StatsHonestComputation.dev.vk@v0".into(),
            public_inputs: vec!["1".into(), "0".into()],
        }
    }

    #[test]
    fn upsert_then_get_roundtrips() {
        let db = temp_db("rt");
        let row = upsert_submission(&db, &sample("t1", Some("a1")), 100).unwrap();
        assert_eq!(row.claimed_value, 950);
        let got = get_one(&db, "t1", Some("a1"), "success_rate", 0)
            .unwrap()
            .expect("row present");
        assert_eq!(got.claimed_value, 950);
        assert_eq!(got.submitted_at, 100);
    }

    #[test]
    fn upsert_is_idempotent() {
        let db = temp_db("idem");
        let mut s = sample("t2", None);
        upsert_submission(&db, &s, 100).unwrap();
        s.claimed_value = 800; // new value
        upsert_submission(&db, &s, 200).unwrap();
        let got = get_one(&db, "t2", None, "success_rate", 0)
            .unwrap()
            .unwrap();
        assert_eq!(got.claimed_value, 800);
        assert_eq!(got.submitted_at, 200);
    }

    #[test]
    fn list_cohort_returns_per_tenant_rows() {
        let db = temp_db("cohort");
        upsert_submission(&db, &sample("t1", None), 100).unwrap();
        upsert_submission(&db, &sample("t2", None), 110).unwrap();
        let rows = list_cohort(&db, "success_rate", 0, 60).unwrap();
        assert_eq!(rows.len(), 2);
        let tenants: Vec<_> = rows.iter().map(|r| r.tenant_id.as_str()).collect();
        assert!(tenants.contains(&"t1") && tenants.contains(&"t2"));
    }

    #[test]
    fn anchor_writes_receipt_with_synthetic_hash() {
        let db = temp_db("anchor");
        let sub = sample("t1", None);
        let hash = anchor_submission(&db, &sub, 100).unwrap();
        assert_eq!(hash, synthetic_action_hash(&sub.merkle_root, &sub.metric_id));
        // Receipt landed.
        let conn = db.lock().unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM agent_action_receipts WHERE action_hash = ?1",
                [&hash],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "exactly one anchored receipt");
    }

    #[test]
    fn synthetic_action_hash_is_deterministic_per_root_metric() {
        let h1 = synthetic_action_hash("ab", "success_rate");
        let h2 = synthetic_action_hash("ab", "success_rate");
        let h3 = synthetic_action_hash("ab", "cost_total");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn tenant_isolation_in_get_one() {
        let db = temp_db("iso");
        upsert_submission(&db, &sample("t1", None), 100).unwrap();
        // Same metric_id + period but different tenant must return None.
        let got = get_one(&db, "t2", None, "success_rate", 0).unwrap();
        assert!(got.is_none(), "tenant isolation broken");
    }
}

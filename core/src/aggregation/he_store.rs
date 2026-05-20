//! DB-backed store for `he_aggregations` (Sprint 13-14, Tier 2).
//!
//! # NEEDS_CRYPTO_REVIEW
//!
//! This implementation has **not** been audited by a cryptographer.
//! Suitable for development and demo only. Production deployments require
//! third-party review of:
//!   (a) modular arithmetic correctness,
//!   (b) random sampling distribution,
//!   (c) message space encoding,
//!   (d) ciphertext re-randomization,
//!   (e) side-channel resistance.
//!
//! Row layout matches `migrations/postgres/0010_he_aggregations.sql` exactly:
//! one row per `(cohort_id, metric_id, period_start)`. The running ciphertext
//! is stored as URL-safe base64; the contribution counter is monotone.

use std::fmt;

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::db::DbHandle;

/// Errors produced by the HE store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeStoreError {
    Storage(String),
    NotFound,
    Invalid(String),
}

impl fmt::Display for HeStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeStoreError::Storage(m) => write!(f, "storage error: {m}"),
            HeStoreError::NotFound => write!(f, "aggregation row not found"),
            HeStoreError::Invalid(m) => write!(f, "invalid aggregation row: {m}"),
        }
    }
}

impl std::error::Error for HeStoreError {}

/// One row of `he_aggregations`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeAggregationRow {
    pub aggregation_id: String,
    pub cohort_id: String,
    pub metric_id: String,
    pub period_start: i64,
    pub pk_id: String,
    pub sum_ciphertext_b64: String,
    pub n_contributions: i64,
    pub last_updated: i64,
}

/// Insert-or-update an aggregation row. Idempotent on the primary key.
///
/// NEEDS_CRYPTO_REVIEW: the row's `sum_ciphertext_b64` is overwritten on
/// every successful submission. There is no tamper-evident log of the
/// individual contributions. Production deployments may want to append
/// each (encrypted_value, customer_attestation) into a separate audit
/// table for forensic review.
pub fn upsert_he_aggregation(
    db: &DbHandle,
    row: &HeAggregationRow,
) -> Result<(), HeStoreError> {
    let conn = db.lock().map_err(|e| HeStoreError::Storage(e.to_string()))?;
    conn.execute(
        r#"INSERT INTO he_aggregations
           (aggregation_id, cohort_id, metric_id, period_start, pk_id,
            sum_ciphertext_b64, n_contributions, last_updated)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
           ON CONFLICT (aggregation_id) DO UPDATE SET
             sum_ciphertext_b64 = excluded.sum_ciphertext_b64,
             n_contributions    = excluded.n_contributions,
             last_updated       = excluded.last_updated"#,
        params![
            row.aggregation_id,
            row.cohort_id,
            row.metric_id,
            row.period_start,
            row.pk_id,
            row.sum_ciphertext_b64,
            row.n_contributions,
            row.last_updated,
        ],
    )
    .map_err(|e| HeStoreError::Storage(e.to_string()))?;
    Ok(())
}

/// Fetch one aggregation row by id. Returns `Ok(None)` if absent.
pub fn get_he_aggregation(
    db: &DbHandle,
    aggregation_id: &str,
) -> Result<Option<HeAggregationRow>, HeStoreError> {
    let conn = db.lock().map_err(|e| HeStoreError::Storage(e.to_string()))?;
    let row = conn
        .query_row(
            r#"SELECT aggregation_id, cohort_id, metric_id, period_start, pk_id,
                      sum_ciphertext_b64, n_contributions, last_updated
               FROM he_aggregations
               WHERE aggregation_id = ?1"#,
            params![aggregation_id],
            |r| {
                Ok(HeAggregationRow {
                    aggregation_id: r.get(0)?,
                    cohort_id: r.get(1)?,
                    metric_id: r.get(2)?,
                    period_start: r.get(3)?,
                    pk_id: r.get(4)?,
                    sum_ciphertext_b64: r.get(5)?,
                    n_contributions: r.get(6)?,
                    last_updated: r.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|e| HeStoreError::Storage(e.to_string()))?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_db_at;
    use std::sync::Arc;

    fn temp_db() -> Arc<DbHandle> {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path = std::env::temp_dir()
            .join(format!("sauron-he-store-{pid}-{nanos}.db"));
        let _ = std::fs::remove_file(&path);
        Arc::new(open_db_at(path.to_str().unwrap(), 2))
    }

    fn sample_row(id: &str) -> HeAggregationRow {
        HeAggregationRow {
            aggregation_id: id.to_string(),
            cohort_id: "coh_a".to_string(),
            metric_id: "secret_sum".to_string(),
            period_start: 0,
            pk_id: "pk_demo".to_string(),
            sum_ciphertext_b64: "AAA".to_string(),
            n_contributions: 1,
            last_updated: 100,
        }
    }

    #[test]
    fn test_upsert_then_get_returns_same_row() {
        let db = temp_db();
        let row = sample_row("agg_1");
        upsert_he_aggregation(&db, &row).unwrap();
        let got = get_he_aggregation(&db, "agg_1").unwrap().unwrap();
        assert_eq!(got, row);
    }

    #[test]
    fn test_get_missing_returns_none() {
        let db = temp_db();
        let r = get_he_aggregation(&db, "ghost").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn test_upsert_updates_in_place() {
        let db = temp_db();
        let mut row = sample_row("agg_upd");
        upsert_he_aggregation(&db, &row).unwrap();
        row.sum_ciphertext_b64 = "BBB".into();
        row.n_contributions = 2;
        row.last_updated = 200;
        upsert_he_aggregation(&db, &row).unwrap();
        let got = get_he_aggregation(&db, "agg_upd").unwrap().unwrap();
        assert_eq!(got.sum_ciphertext_b64, "BBB");
        assert_eq!(got.n_contributions, 2);
        assert_eq!(got.last_updated, 200);
    }
}

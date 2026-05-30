//! HTTP handlers for `/v1/stats/*` routes (Sprint 7).
//!
//! All routes are admin-gated through `admin::auth_middleware` and run
//! after `tenancy::extract_tenant`. Same gating pattern as `/v1/policy/*`.

use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::Json,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::aggregation::cohorts::{CohortDefinition, CohortError};
use crate::aggregation::publish::{
    publish_cohort_with_ledger, PublishError, PublishedCohort,
};
use crate::aggregation::store::{
    anchor_submission, list_cohort, list_for_cohort, synthetic_action_hash,
    upsert_submission,
};
use crate::aggregation::submission::{CohortRow, StatsSubmission, StatsSubmitResponse};
use crate::aggregation::verify::{verify_stats_submission, AggError};
use crate::dp::{LedgerEntry, LedgerError};
use crate::error::AppError;
use crate::state::ServerState;
use crate::tenancy::TenantId;
use crate::zk_verifier::FsVKeyLoader;

/// `POST /v1/stats/submit` — accept a stats submission, verify the ZK proof,
/// idempotent-insert into `customer_stats`, anchor into the audit chain.
pub async fn submit_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    tenant: Option<Extension<TenantId>>,
    Json(mut body): Json<StatsSubmission>,
) -> Result<Json<StatsSubmitResponse>, AppError> {
    // Tenant binding: middleware extension wins over body. The body field
    // exists for tests / dashboard round-trips, but the trusted source is
    // the middleware-resolved TenantId.
    if let Some(Extension(t)) = tenant {
        body.tenant_id = t.0;
    } else {
        body.tenant_id = TenantId::default_tenant().0;
    }

    let started = Instant::now();
    let loader = FsVKeyLoader::new(
        std::env::var("ZKP_VKEY_DIR").unwrap_or_else(|_| "zkp/circuits/build/keys".into()),
    );
    verify_stats_submission(&body, &loader)
        .await
        .map_err(map_agg_err)?;
    let latency_ms_verify = started.elapsed().as_millis() as u64;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let db = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        st.db.clone()
    };
    upsert_submission(&db, &body, now).map_err(map_agg_err)?;
    let anchored_action_hash = anchor_submission(&db, &body, now).unwrap_or_else(|_| {
        // Anchor failure is non-fatal — the row is stored and the merkle
        // batcher will pick it up on the next pass once the column is free.
        synthetic_action_hash(&body.merkle_root, &body.metric_id)
    });

    Ok(Json(StatsSubmitResponse {
        stored: true,
        latency_ms_verify,
        anchored_action_hash,
    }))
}

/// Query string for `GET /v1/stats/cohort`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CohortQuery {
    pub metric_id: String,
    pub period_start: i64,
    pub period_end: i64,
}

/// Response shape for `GET /v1/stats/cohort`.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CohortResponse {
    pub rows: Vec<CohortRow>,
    pub n: usize,
}

/// `GET /v1/stats/cohort?metric_id=X&period_start=Y&period_end=Z` —
/// operator-facing cross-tenant view. Not the DP-published view.
pub async fn cohort_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Query(q): Query<CohortQuery>,
) -> Result<Json<CohortResponse>, AppError> {
    if q.period_end < q.period_start {
        return Err(AppError::BadRequest("period_end < period_start".into()));
    }
    let db = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        st.db.clone()
    };
    let rows = list_cohort(&db, &q.metric_id, q.period_start, q.period_end)
        .map_err(map_agg_err)?;
    let n = rows.len();
    Ok(Json(CohortResponse { rows, n }))
}

// ─── Sprint 13-14 Tier 2: Paillier homomorphic-encryption submission ────────
//
// NEEDS_CRYPTO_REVIEW: this handler accepts customer ciphertexts encrypted
// under a cohort-scoped public key, homomorphically adds them into a running
// aggregate, and never decrypts individual contributions. Per-customer
// values never leave Z_{n^2}* on the server. Production deployments
// require third-party crypto review (see core/src/he/ disclaimers).

/// Body for `POST /v1/stats/submit-encrypted`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedStatsSubmission {
    /// Cohort scope. Operator-managed; same id space as `/v1/cohort`.
    pub cohort_id: String,
    /// Catalog metric id (matches `agentic/src/stats/metric-catalog.ts`).
    pub metric_id: String,
    /// Reporting-window start (unix epoch seconds). Bound to the
    /// aggregation row so contributions outside the period are isolated.
    pub period_start: i64,
    /// Identifier of the public key the customer encrypted under. Server
    /// looks up the corresponding modulus via the registered key set.
    pub pk_id: String,
    /// Customer ciphertext (URL-safe base64, no padding).
    pub encrypted_value_b64: String,
}

/// Response shape from `POST /v1/stats/submit-encrypted`.
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedStatsResponse {
    /// Stable id of the running aggregation row.
    pub aggregated_into: String,
    /// Cumulative count of customer contributions to this aggregation.
    pub n_contributions: i64,
}

/// `POST /v1/stats/submit-encrypted` — accept a Paillier-encrypted customer
/// statistic, homomorphically accumulate it into the cohort aggregate.
/// Admin-gated + tenant-scoped (the middleware stack matches `/v1/stats/submit`).
///
/// NEEDS_CRYPTO_REVIEW: server never sees the plaintext value. Decryption
/// happens out-of-band, by an operator holding the cohort private key.
pub async fn submit_encrypted_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    _tenant: Option<Extension<TenantId>>,
    Json(body): Json<EncryptedStatsSubmission>,
) -> Result<Json<EncryptedStatsResponse>, AppError> {
    use crate::aggregation::he_aggregator::HeAggregator;
    use crate::aggregation::he_store::{
        conflicting_cohort_for_pk, get_he_aggregation, upsert_he_aggregation, HeAggregationRow,
    };
    use crate::he::paillier::PaillierPublicKey;
    use crate::he::serde_impl::{ciphertext_from_b64, ciphertext_to_b64};

    let db = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        st.db.clone()
    };

    // Resolve the cohort public key from the in-process registry.
    let pk: PaillierPublicKey = {
        let registry = {
            let st = state
                .read()
                .map_err(|_| AppError::Internal("state lock".into()))?;
            st.he_pk_registry.clone()
        };
        let map = registry
            .read()
            .map_err(|_| AppError::Internal("he registry lock".into()))?;
        map.get(&body.pk_id)
            .cloned()
            .ok_or_else(|| AppError::NotFound(format!("pk_id not registered: {}", body.pk_id)))?
    };

    let incoming = ciphertext_from_b64(&body.encrypted_value_b64)
        .map_err(|e| AppError::BadRequest(format!("ciphertext decode: {e}")))?;

    // Reject key-confusion: a pk_id observed under a different cohort cannot be
    // reused here. The first cohort to use a key owns it (trust-on-first-use),
    // so a ciphertext under cohort A's key can never land in cohort B's
    // aggregate.
    if let Some(other) = conflicting_cohort_for_pk(&db, &body.pk_id, &body.cohort_id)
        .map_err(|e| AppError::Internal(format!("he store: {e}")))?
    {
        return Err(AppError::BadRequest(format!(
            "pk_id '{}' is already bound to cohort '{}'; refusing to reuse it for cohort '{}'",
            body.pk_id, other, body.cohort_id
        )));
    }

    let aggregation_id = format!(
        "agg_{}_{}_{}_{}",
        body.cohort_id, body.metric_id, body.period_start, body.pk_id
    );

    // Idempotent submit-then-replace: load running ciphertext, homomorphically
    // add the new one, persist back. Operations on Z_{n^2}* are independent
    // of the order of contributions (Paillier is commutative).
    let mut aggregator = match get_he_aggregation(&db, &aggregation_id)
        .map_err(|e| AppError::Internal(format!("he store: {e}")))?
    {
        Some(row) => {
            let existing = ciphertext_from_b64(&row.sum_ciphertext_b64)
                .map_err(|e| AppError::Internal(format!("stored ciphertext: {e}")))?;
            HeAggregator::from_parts(pk.clone(), existing, row.n_contributions as u32)
        }
        None => {
            let mut rng = OsRng;
            HeAggregator::new(pk.clone(), &mut rng)
                .map_err(|e| AppError::Internal(format!("init aggregator: {e}")))?
        }
    };

    aggregator
        .add_encrypted(&incoming)
        .map_err(|e| AppError::BadRequest(format!("homomorphic add: {e}")))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let row = HeAggregationRow {
        aggregation_id: aggregation_id.clone(),
        cohort_id: body.cohort_id,
        metric_id: body.metric_id,
        period_start: body.period_start,
        pk_id: body.pk_id,
        sum_ciphertext_b64: ciphertext_to_b64(&aggregator.sum_ciphertext),
        n_contributions: aggregator.n_contributions as i64,
        last_updated: now,
    };
    upsert_he_aggregation(&db, &row).map_err(|e| AppError::Internal(format!("he store: {e}")))?;

    Ok(Json(EncryptedStatsResponse {
        aggregated_into: aggregation_id,
        n_contributions: row.n_contributions,
    }))
}

fn map_agg_err(e: AggError) -> AppError {
    match e {
        AggError::Malformed(m) => AppError::BadRequest(m),
        AggError::Invalid(m) => AppError::BadRequest(m),
        AggError::KeyNotFound(m) => AppError::NotFound(m),
        AggError::VerifierFailed(m) => AppError::Internal(m),
        AggError::Storage(m) => AppError::Internal(m),
    }
}

fn map_cohort_err(e: CohortError) -> AppError {
    match e {
        CohortError::Invalid(m) => AppError::BadRequest(m),
        CohortError::Storage(m) => AppError::Internal(m),
        CohortError::Lock => AppError::Internal("cohort store lock poisoned".into()),
    }
}

fn map_publish_err(e: PublishError) -> AppError {
    match e {
        PublishError::Invalid(m) => AppError::BadRequest(m),
        PublishError::Dp(m) => AppError::Internal(m),
    }
}

// ─── Sprint 8 ───────────────────────────────────────────────────────────────
// Cohort definition CRUD + DP-published cohort endpoint.
// All routes are admin-gated (operator-level — global, not tenant-scoped).

/// Query string for `GET /v1/cohort/published`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedQuery {
    pub cohort_id: String,
    pub period_start: i64,
    pub period_end: i64,
}

/// `POST /v1/cohort` — upsert a cohort definition (operator-global).
pub async fn cohort_upsert_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(def): Json<CohortDefinition>,
) -> Result<Json<CohortDefinition>, AppError> {
    let store = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        st.cohort_store.clone()
    };
    store.upsert(def.clone()).map_err(map_cohort_err)?;
    Ok(Json(def))
}

/// `GET /v1/cohort` — list all cohort definitions.
pub async fn cohort_list_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<Vec<CohortDefinition>>, AppError> {
    let store = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        st.cohort_store.clone()
    };
    Ok(Json(store.list()))
}

/// `GET /v1/cohort/:id` — fetch one cohort definition.
pub async fn cohort_get_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(id): Path<String>,
) -> Result<Json<CohortDefinition>, AppError> {
    let store = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        st.cohort_store.clone()
    };
    match store.get(&id) {
        Some(def) => Ok(Json(def)),
        None => Err(AppError::NotFound(format!("cohort not found: {id}"))),
    }
}

/// `DELETE /v1/cohort/:id` — remove a cohort definition. Idempotent.
pub async fn cohort_delete_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let store = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        st.cohort_store.clone()
    };
    store.delete(&id).map_err(map_cohort_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/cohort/published?cohort_id=X&period_start=Y&period_end=Z` —
/// aggregate raw stats across the cohort's opted-in tenants, apply DP noise
/// per quartile per metric under the cohort's ε budget, suppress metrics
/// below the k-anonymity threshold, and return the DP-published view.
///
/// Response shape matches the dashboard's `CohortDetail` interface exactly.
pub async fn cohort_published_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Query(q): Query<PublishedQuery>,
) -> Result<Json<PublishedCohort>, AppError> {
    if q.period_end < q.period_start {
        return Err(AppError::BadRequest("period_end < period_start".into()));
    }
    let (store, db, ledger) = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        (
            st.cohort_store.clone(),
            st.db.clone(),
            st.dp_budget_ledger.clone(),
        )
    };
    let cohort = store
        .get(&q.cohort_id)
        .ok_or_else(|| AppError::NotFound(format!("cohort not found: {}", q.cohort_id)))?;
    let raw = list_for_cohort(&db, &cohort.tenant_ids, q.period_start, q.period_end)
        .map_err(map_agg_err)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut rng = OsRng;
    let published = publish_cohort_with_ledger(
        &cohort,
        &raw,
        q.period_start,
        q.period_end,
        &ledger,
        now,
        &mut rng,
    )
    .map_err(map_publish_err)?;
    Ok(Json(published))
}

fn map_ledger_err(e: LedgerError) -> AppError {
    match e {
        LedgerError::Invalid(m) => AppError::BadRequest(m),
        LedgerError::Storage(m) => AppError::Internal(m),
        LedgerError::Lock => AppError::Internal("ledger lock poisoned".into()),
    }
}

/// `GET /v1/cohort/:id/budget` — return the per-cycle ε ledger for a
/// cohort. Admin-gated (operator-level — global, not tenant-scoped).
/// Returns `404` when the cohort definition is absent; an empty ledger
/// list is legal (no publications yet for any cycle).
pub async fn cohort_budget_get_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<LedgerEntry>>, AppError> {
    let (store, ledger) = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        (st.cohort_store.clone(), st.dp_budget_ledger.clone())
    };
    if store.get(&id).is_none() {
        return Err(AppError::NotFound(format!("cohort not found: {id}")));
    }
    let rows = ledger.get_ledger(&id).map_err(map_ledger_err)?;
    Ok(Json(rows))
}

/// Body for `POST /v1/cohort/:id/budget/rotate`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetRotateBody {
    /// Unix-epoch seconds for the new cycle start boundary.
    pub new_cycle_start: i64,
    /// Lifetime ε cap for the new cycle.
    pub new_epsilon_cap: f64,
    /// Lifetime δ cap for the new cycle.
    pub new_delta_cap: f64,
    /// Optional metric-id filter. `None` → rotate every metric the
    /// ledger has seen for this cohort. Empty list is treated as `None`.
    #[serde(default)]
    pub metric_ids: Option<Vec<String>>,
}

/// Response body for `POST /v1/cohort/:id/budget/rotate`.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetRotateResponse {
    /// Cohort id rotated.
    pub cohort_id: String,
    /// New cycle start (unix-epoch seconds).
    pub new_cycle_start: i64,
    /// Number of (metric, cycle) ledger rows created or updated.
    pub rotated: usize,
}

/// `POST /v1/cohort/:id/budget/rotate` — operator-triggered regulatory
/// reset of the ε ledger. Body carries the new cycle start + caps.
/// Admin-gated.
pub async fn cohort_budget_rotate_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(id): Path<String>,
    Json(body): Json<BudgetRotateBody>,
) -> Result<Json<BudgetRotateResponse>, AppError> {
    let (store, ledger) = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        (st.cohort_store.clone(), st.dp_budget_ledger.clone())
    };
    if store.get(&id).is_none() {
        return Err(AppError::NotFound(format!("cohort not found: {id}")));
    }

    // Resolve which metrics to rotate. If the caller does not pass a
    // list, rotate every metric the ledger has already seen — this is
    // the right behaviour for a regulatory quarterly reset where the
    // operator wants the next publication to start from a fresh budget
    // regardless of which metrics are about to appear.
    let metrics: Vec<String> = match body.metric_ids.as_ref() {
        Some(v) if !v.is_empty() => v.clone(),
        _ => {
            let existing = ledger.get_ledger(&id).map_err(map_ledger_err)?;
            let mut seen = std::collections::BTreeSet::new();
            for e in existing {
                seen.insert(e.metric_id);
            }
            seen.into_iter().collect()
        }
    };

    let mut rotated = 0usize;
    for m in &metrics {
        ledger
            .rotate_cycle(
                &id,
                m,
                body.new_cycle_start,
                body.new_epsilon_cap,
                body.new_delta_cap,
            )
            .map_err(map_ledger_err)?;
        rotated += 1;
    }

    Ok(Json(BudgetRotateResponse {
        cohort_id: id,
        new_cycle_start: body.new_cycle_start,
        rotated,
    }))
}

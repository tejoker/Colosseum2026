//! HTTP handlers for `/v1/audit/reports/*` — Sprint 19-20.
//!
//! All routes admin-gated (mirrors `/v1/stats/*` wiring) and
//! tenant-scoped via `Extension<TenantId>`.

use std::sync::{Arc, RwLock};

use axum::{
    extract::{Extension, Path, Query, State},
    response::Json,
};
use serde::{Deserialize, Serialize};

use crate::audit::builder::{build_audit_report, AuditError, BuildRequest};
use crate::audit::report::{sign_report, AuditReport};
use crate::audit::store::{get_report, list_reports, store_report, StoreError};
use crate::error::AppError;
use crate::state::ServerState;
use crate::tenancy::TenantId;

/// `POST /v1/audit/reports` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateReportRequest {
    /// Optional explicit agent scope. `None` ⇒ all agents that
    /// emitted receipts in the period.
    #[serde(default)]
    pub agent_ids: Option<Vec<String>>,
    /// Unix epoch seconds — inclusive lower bound of the period.
    pub period_start: i64,
    /// Unix epoch seconds — inclusive upper bound of the period.
    pub period_end: i64,
}

/// Response envelope for `POST /v1/audit/reports` — the freshly-built
/// report plus its internal integrity MAC.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateReportResponse {
    /// The full report (also accessible via
    /// `GET /v1/audit/reports/:id`).
    pub report: AuditReport,
    /// Hex-encoded, domain-separated HMAC-SHA256 integrity tag over the
    /// report's canonical form. This is not a public signature.
    pub signature: String,
}

/// Query string for `GET /v1/audit/reports?limit=…`.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    /// Page size cap. Default 100, capped at 1000.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// `POST /v1/audit/reports` — generate, store, and return a new
/// audit report. Tenant-scoped through `Extension<TenantId>`.
pub async fn create_report_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Extension(tenant): Extension<TenantId>,
    Json(body): Json<CreateReportRequest>,
) -> Result<Json<CreateReportResponse>, AppError> {
    let build = BuildRequest {
        agent_ids: body.agent_ids,
        period_start: body.period_start,
        period_end: body.period_end,
    };
    let report = build_audit_report(state.clone(), tenant.as_str(), build)
        .await
        .map_err(map_audit_err)?;

    let (db, sign_key) = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        // sign_report derives a dedicated HKDF subkey, so device tokens and
        // report MACs never use the same effective key.
        (st.db.clone(), st.token_secret.clone())
    };

    let signature = sign_report(&report, &sign_key);
    store_report(&db, &report, &signature).map_err(map_store_err)?;

    Ok(Json(CreateReportResponse { report, signature }))
}

/// `GET /v1/audit/reports/:id` — fetch a stored report.
pub async fn get_report_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Extension(tenant): Extension<TenantId>,
    Path(id): Path<String>,
) -> Result<Json<AuditReport>, AppError> {
    let db = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        st.db.clone()
    };
    match get_report(&db, tenant.as_str(), &id).map_err(map_store_err)? {
        Some(r) => Ok(Json(r)),
        None => Err(AppError::NotFound(format!("audit report {id} not found"))),
    }
}

/// `GET /v1/audit/reports` — list stored reports, newest first.
pub async fn list_reports_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
    Extension(tenant): Extension<TenantId>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<AuditReport>>, AppError> {
    let db = {
        let st = state
            .read()
            .map_err(|_| AppError::Internal("state lock".into()))?;
        st.db.clone()
    };
    let limit = q.limit.unwrap_or(100);
    let rows = list_reports(&db, tenant.as_str(), limit).map_err(map_store_err)?;
    Ok(Json(rows))
}

fn map_audit_err(e: AuditError) -> AppError {
    match e {
        AuditError::Invalid(m) => AppError::BadRequest(m),
        AuditError::Storage(m) => AppError::Internal(m),
    }
}

fn map_store_err(e: StoreError) -> AppError {
    match e {
        StoreError::Db(m) => AppError::Internal(m),
        StoreError::Decode(m) => AppError::Internal(m),
    }
}

use axum::{
    extract::Json as AxumJson, http::StatusCode, middleware, routing::get, routing::post, Router,
};
use serde::Deserialize;
use std::sync::{Arc, RwLock};

use crate::{
    admin, aggregation::handlers as agg_handlers, attestation::handlers as attestation_handlers,
    audit::handlers as audit_report_handlers, middleware::audit_log, policy::binding_handlers,
    policy::handlers as policy_handlers, rings, state::ServerState, tenancy, usage, zk_verifier,
};

/// Router for `/v1/policy/*` — Sprint 2 policy DSL endpoints.
///
/// All routes are gated by `admin::auth_middleware` (same middleware as
/// `/admin/*`) — these are operator endpoints, not browser-facing.
pub fn policy_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route("/upload", post(policy_handlers::upload))
        .route("/list", get(policy_handlers::list))
        .route("/evaluate", post(policy_handlers::evaluate_action))
        .route(
            "/{id}",
            get(policy_handlers::get_one).delete(policy_handlers::delete_one),
        )
        // Tenant extraction MUST run before admin auth so the resolved
        // `TenantId` is in `Extensions` regardless of whether the route
        // requires JWT auth or static-key auth.
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

/// Router for `/v1/agents/:agent_id/spend*` — Sprint 3 follow-up
/// authoritative spend ledger plus Sprint 10 server-side policy binding.
/// Same admin gating as `/v1/policy/*`.
///
/// Routes:
/// - `POST   /v1/agents/:agent_id/spend`           — append one spend record.
/// - `GET    /v1/agents/:agent_id/spend`           — current ledger summary.
/// - `GET    /v1/agents/:agent_id/spend/log`       — recent log rows.
/// - `POST   /v1/agents/:agent_id/policy_binding`  — bind agent to a policy.
/// - `GET    /v1/agents/:agent_id/policy_binding`  — current binding (or 404).
/// - `DELETE /v1/agents/:agent_id/policy_binding`  — drop the binding.
pub fn agent_spend_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route(
            "/{agent_id}/spend",
            post(policy_handlers::record_spend).get(policy_handlers::get_spend),
        )
        .route(
            "/{agent_id}/spend/log",
            get(policy_handlers::list_spend_log_handler),
        )
        .route(
            "/{agent_id}/policy_binding",
            post(binding_handlers::bind_policy)
                .get(binding_handlers::get_binding)
                .delete(binding_handlers::unbind_policy),
        )
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

/// Router for `/v1/proofs/*` — Sprint 4 action-log proof verification.
///
/// `POST /v1/proofs/action-log/verify` consumes an `ActionLogProofPayload`
/// plus an `expected_root_hex` and replies 200 on accept, 400 on reject.
/// Admin-gated; the proof verification is computationally cheap relative to
/// proving but still gated to avoid being an oracle for arbitrary callers.
pub fn proofs_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route("/action-log/verify", post(action_log_verify_handler))
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

#[derive(Debug, Deserialize)]
pub struct ActionLogVerifyRequest {
    #[serde(flatten)]
    pub payload: zk_verifier::ActionLogProofPayload,
    // SECURITY: `expected_root_hex` is still caller-supplied. It MUST be bound to
    // an authoritative, finalized server checkpoint (tenant + tree size + anchor
    // id) rather than trusted verbatim — tracked with the proof-statement
    // redesign in docs/design/zk-proof-statement.md. Until then this route only
    // proves internal consistency with the supplied root, NOT with the server's
    // authoritative log; treat its 200 accordingly.
    pub expected_root_hex: String,
    // `vkey_dir` was request-controlled — a caller could point verification at an
    // attacker-supplied verification key (or traverse the filesystem). REMOVED:
    // the verification-key directory is now server-controlled only (ZKP_VKEY_DIR
    // env, else the built-in default). Any `vkey_dir` field in the body is
    // ignored by serde (no field), so old clients simply lose the override.
}

async fn action_log_verify_handler(
    AxumJson(body): AxumJson<ActionLogVerifyRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Server-controlled ONLY — never from the request.
    let dir = std::env::var("ZKP_VKEY_DIR").unwrap_or_else(|_| "zkp/circuits/build/keys".to_string());
    let loader = zk_verifier::FsVKeyLoader::new(dir);

    match zk_verifier::verify_action_log_proof(&body.payload, &body.expected_root_hex, &loader)
        .await
    {
        Ok(()) => Ok(StatusCode::OK),
        Err(zk_verifier::ZkVerifyError::Malformed(m)) => {
            Err((StatusCode::BAD_REQUEST, format!("malformed: {m}")))
        }
        Err(zk_verifier::ZkVerifyError::KeyNotFound(m)) => {
            Err((StatusCode::NOT_FOUND, format!("vkey missing: {m}")))
        }
        Err(zk_verifier::ZkVerifyError::Invalid(m)) => {
            Err((StatusCode::BAD_REQUEST, format!("invalid proof: {m}")))
        }
        Err(zk_verifier::ZkVerifyError::VerifierFailed(m)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("verifier process failed: {m}"),
        )),
    }
}

/// Router for `/v1/stats/*` — Sprint 7 customer stat aggregation + ZK integrity.
///
/// `POST /v1/stats/submit`  — body = [`crate::aggregation::StatsSubmission`].
///                            Verifies the proof, upserts the row, anchors it.
/// `GET  /v1/stats/cohort`  — operator-facing cross-tenant view. Not the DP
///                            publish path (that's Sprint 8 + Sprint 9).
///
/// Both admin-gated through the same middleware stack as `/v1/policy/*`.
pub fn stats_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route("/submit", post(agg_handlers::submit_handler))
        // Sprint 13-14 Tier 2: optional Paillier-encrypted submission path.
        // NEEDS_CRYPTO_REVIEW — see core/src/he/ disclaimer block.
        .route(
            "/submit-encrypted",
            post(agg_handlers::submit_encrypted_handler),
        )
        .route("/cohort", get(agg_handlers::cohort_handler))
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

/// Router for `/v1/cohort/*` — Sprint 8 DP-published cohort surface.
///
/// All routes are admin-gated (operator-level — global, not tenant-scoped):
///
/// - `POST   /v1/cohort`            — upsert a cohort definition.
/// - `GET    /v1/cohort`            — list all cohort definitions.
/// - `GET    /v1/cohort/published`  — DP-published cohort aggregate
///                                    (cohort_id, period_start, period_end).
/// - `GET    /v1/cohort/{id}`       — fetch one cohort definition.
/// - `DELETE /v1/cohort/{id}`       — delete a cohort definition.
///
/// IMPORTANT route ordering: `/published` is declared before `/{id}` so axum
/// matches the literal segment first instead of treating "published" as an
/// id capture.
pub fn cohort_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route(
            "/",
            post(agg_handlers::cohort_upsert_handler).get(agg_handlers::cohort_list_handler),
        )
        .route("/published", get(agg_handlers::cohort_published_handler))
        // S8 ext: per-cohort ε ledger surface. Both routes admin-gated;
        // the rotate route is operator-only (regulatory quarterly reset).
        // Declared BEFORE the catch-all `/{id}` so axum prefers the
        // literal segments.
        .route("/{id}/budget", get(agg_handlers::cohort_budget_get_handler))
        .route(
            "/{id}/budget/rotate",
            post(agg_handlers::cohort_budget_rotate_handler),
        )
        .route(
            "/{id}",
            get(agg_handlers::cohort_get_handler).delete(agg_handlers::cohort_delete_handler),
        )
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

/// Router for `/v1/admin/audit` — S12 security audit log query.
///
/// Admin-gated, tenant-scoped. Operators query their own tenant's
/// audit trail; the layer that emits records lives in
/// `core/src/middleware/audit_log.rs`.
pub fn audit_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route("/", get(audit_log::admin_audit_handler))
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

/// Router for `/v1/audit/reports/*` — Sprint 19-20 periodic audit report.
///
/// Admin-gated, tenant-scoped. Routes:
/// - `POST   /v1/audit/reports`      — generate + store a new report.
/// - `GET    /v1/audit/reports`      — list stored reports.
/// - `GET    /v1/audit/reports/:id`  — fetch a single report.
pub fn audit_reports_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route(
            "/reports",
            post(audit_report_handlers::create_report_handler)
                .get(audit_report_handlers::list_reports_handler),
        )
        .route(
            "/reports/{id}",
            get(audit_report_handlers::get_report_handler),
        )
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

/// Router for `/v1/attestation/*` — Sprint 6 dedicated attestation surface.
///
/// Today this nests a single route — `POST /v1/attestation/nitro/verify` —
/// that runs the full AWS Nitro COSE_Sign1 + CBOR verification flow and
/// returns the parsed `module_id`, PCR set, and a structured `valid` /
/// `error` envelope. Admin-gated + tenant-scoped (same middleware stack as
/// `/v1/policy/*`).
///
/// Future hardware kinds (TPM2 quote upload, SGX quote, SEV-SNP report)
/// slot into sibling routes under the same router.
pub fn attestation_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route(
            "/nitro/verify",
            post(attestation_handlers::nitro_verify_handler),
        )
        .route_layer(middleware::from_fn(admin::auth_middleware))
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

pub fn admin_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route("/clients", post(admin::add_client).get(admin::get_clients))
        .route("/users", get(admin::get_users))
        .route("/site/{name}/users", get(admin::get_site_users))
        .route("/site/{name}/zkp_proofs", get(admin::get_site_zkp_proofs))
        .route("/requests", get(admin::get_requests))
        .route("/stats", get(admin::get_stats))
        .route(
            "/anchor/agent-actions/proof",
            get(admin::get_action_anchor_proof),
        )
        .route(
            "/anchor/agent-actions/run",
            post(admin::force_action_anchor_run),
        )
        // ADR-001: per-batch three-state surface (solana.confirmed / bitcoin.ots_upgraded)
        .route("/anchor/batches", get(admin::get_anchor_batches))
        // Download the OpenTimestamps `.ots` proof for a batch's BTC anchor.
        .route("/anchor/ots/{anchor_id}", get(admin::get_anchor_ots))
        // Live-data analytics endpoints (Analytics 5/5 — replaces parquet path)
        .route("/agents", get(admin::get_agents))
        .route("/agents/{agent_id}/revoke", post(admin::revoke_agent_admin))
        .route("/agent_actions/recent", get(admin::get_recent_actions))
        // Dashboard "Try" page — runs real governance scenarios (replay/scope/normal).
        .route("/demo/scenario/{scenario}", post(admin::run_demo_scenario))
        .route("/anchor/status", get(admin::get_anchor_status))
        .route("/per_agent_metrics", get(admin::get_per_agent_metrics))
        .route("/egress/recent", get(admin::get_recent_egress))
        .route("/checksum/audit/{agent_id}", get(admin::get_checksum_audit))
        .route("/health/detailed", get(admin::health))
        // Anonymous ring-policy admin ops (phase 2; gated by SAURON_ANON_RINGS).
        .route(
            "/rings",
            post(rings::create_ring_handler).get(rings::list_rings_handler),
        )
        .route("/rings/{ring_id}/subscribe", post(rings::subscribe_handler))
        .route("/rings/{ring_id}/revoke", post(rings::revoke_handler))
        .route("/rings/{ring_id}/members", get(rings::members_handler))
        .route("/rings/{ring_id}/usage", get(usage::ring_usage_handler))
        .route_layer(middleware::from_fn(admin::auth_middleware))
        // Admin endpoints aggregate across tenants by default — they are
        // operator-global. Per-endpoint tenant filtering is layered in
        // 11.5; today the operator MUST treat `/admin/*` output as
        // cross-tenant aggregate (see docs/multi-tenancy.md §"Admin").
        .route_layer(middleware::from_fn(tenancy::extract_tenant))
}

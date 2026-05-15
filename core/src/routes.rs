use axum::{middleware, routing::get, routing::post, Router};
use std::sync::{Arc, RwLock};

use crate::{admin, state::ServerState};

pub fn admin_router() -> Router<Arc<RwLock<ServerState>>> {
    Router::new()
        .route("/clients", post(admin::add_client).get(admin::get_clients))
        .route("/users", get(admin::get_users))
        .route("/site/{name}/users", get(admin::get_site_users))
        .route("/site/{name}/zkp_proofs", get(admin::get_site_zkp_proofs))
        .route("/requests", get(admin::get_requests))
        .route("/stats", get(admin::get_stats))
        .route("/anchor/agent-actions/proof", get(admin::get_action_anchor_proof))
        .route("/anchor/agent-actions/run", post(admin::force_action_anchor_run))
        // ADR-001: per-batch three-state surface (solana.confirmed / bitcoin.ots_upgraded)
        .route("/anchor/batches", get(admin::get_anchor_batches))
        // Live-data analytics endpoints (Analytics 5/5 — replaces parquet path)
        .route("/agents", get(admin::get_agents))
        .route("/agent_actions/recent", get(admin::get_recent_actions))
        .route("/anchor/status", get(admin::get_anchor_status))
        .route("/per_agent_metrics", get(admin::get_per_agent_metrics))
        .route("/egress/recent", get(admin::get_recent_egress))
        .route("/checksum/audit/{agent_id}", get(admin::get_checksum_audit))
        .route("/health/detailed", get(admin::health))
        .route_layer(middleware::from_fn(admin::auth_middleware))
}

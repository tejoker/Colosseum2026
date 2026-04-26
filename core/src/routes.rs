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
        .route_layer(middleware::from_fn(admin::auth_middleware))
}

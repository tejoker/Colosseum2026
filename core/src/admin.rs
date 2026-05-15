use axum::{
    extract::{Path, Request, State},
    http::{header::AUTHORIZATION, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json},
};
use curve25519_dalek::ristretto::CompressedRistretto;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock, RwLock};
use subtle::ConstantTimeEq;

use crate::error::AppError;
use crate::identity::Identity;
use crate::risk;
use crate::runtime_mode::is_development_runtime;
use crate::sites::ClientType;
use crate::state::ServerState;

// ─────────────────────────────────────────────────────
//  Admin authentication (multi-key rotation + optional HS256 JWT)
// ─────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AdminAuthConfig {
    /// Full-access static keys (`x-admin-key`).
    pub full_write_keys: Vec<Vec<u8>>,
    /// Read-only static keys — **GET/HEAD only**.
    pub read_only_keys: Vec<Vec<u8>>,
    /// When set, `Authorization: Bearer <jwt>` is accepted. JWT must include `scp`
    /// with `admin:read` (GET/HEAD), `admin:write` or `admin:full` (mutating), or `admin:super` / `*`.
    pub jwt_hs256_secret: Option<Vec<u8>>,
}

static ADMIN_AUTH: OnceLock<AdminAuthConfig> = OnceLock::new();

/// Call once at process startup after env is loaded.
pub fn init_admin_auth() -> Result<(), String> {
    let cfg = build_admin_auth_config()?;
    ADMIN_AUTH
        .set(cfg)
        .map_err(|_| "admin auth: init_admin_auth called twice".to_string())
}

fn admin_cfg() -> &'static AdminAuthConfig {
    ADMIN_AUTH
        .get()
        .expect("admin auth not initialized (call init_admin_auth at startup)")
}

fn build_admin_auth_config() -> Result<AdminAuthConfig, String> {
    let mut full_write_keys: Vec<Vec<u8>> = Vec::new();
    if let Ok(k) = std::env::var("SAURON_ADMIN_KEY") {
        let t = k.trim();
        if !t.is_empty() {
            full_write_keys.push(t.as_bytes().to_vec());
        }
    }
    if let Ok(list) = std::env::var("SAURON_ADMIN_KEYS") {
        for part in list.split(',') {
            let t = part.trim();
            if !t.is_empty() {
                full_write_keys.push(t.as_bytes().to_vec());
            }
        }
    }
    if full_write_keys.is_empty() {
        if let Some(b) = crate::state::development_fallback_admin_key_material() {
            eprintln!(
                "[WARN] SAURON_ADMIN_KEY / SAURON_ADMIN_KEYS unset — using derived **development** admin key."
            );
            full_write_keys.push(b);
        }
    }

    let mut read_only_keys: Vec<Vec<u8>> = Vec::new();
    if let Ok(list) = std::env::var("SAURON_ADMIN_READ_ONLY_KEYS") {
        for part in list.split(',') {
            let t = part.trim();
            if !t.is_empty() {
                read_only_keys.push(t.as_bytes().to_vec());
            }
        }
    }

    let jwt_hs256_secret = std::env::var("SAURON_ADMIN_JWT_HS256_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| s.into_bytes());

    if !is_development_runtime() {
        if full_write_keys.is_empty() {
            return Err(
                "production requires SAURON_ADMIN_KEY and/or SAURON_ADMIN_KEYS (non-empty)".into(),
            );
        }
        for k in &full_write_keys {
            if k.len() < 32 {
                return Err("production: each full admin key must be >= 32 bytes".into());
            }
        }
        for k in &read_only_keys {
            if k.len() < 32 {
                return Err("production: each read-only admin key must be >= 32 bytes".into());
            }
        }
        if let Some(ref j) = jwt_hs256_secret {
            if j.len() < 32 {
                return Err("production: SAURON_ADMIN_JWT_HS256_SECRET must be >= 32 bytes".into());
            }
        }
    } else if full_write_keys.is_empty() && read_only_keys.is_empty() {
        return Err("development admin auth misconfigured (no keys)".into());
    } else {
        // Warn on the well-known defaults that ship in docs/seed scripts.
        // NOTE: the legacy seed token is included intentionally so deployments
        // that copied it from old docs trip this warning. Do not remove.
        const KNOWN_WEAK: &[&str] = &[
            "super_secret_hackathon_key",
            "changeme",
            "secret",
            "admin",
            "password",
        ];
        for k in &full_write_keys {
            if let Ok(s) = std::str::from_utf8(k) {
                if KNOWN_WEAK.contains(&s) {
                    eprintln!(
                        "[SECURITY WARN] Admin key '{}' is a known-weak default. \
                         Set SAURON_ADMIN_KEY to a strong random secret before exposing this service.",
                        s
                    );
                }
            }
        }
    }

    Ok(AdminAuthConfig {
        full_write_keys,
        read_only_keys,
        jwt_hs256_secret,
    })
}

#[derive(Debug, Deserialize)]
struct AdminJwtClaims {
    #[serde(default)]
    scp: Vec<String>,
    /// Handled by `jsonwebtoken` expiry validation.
    #[allow(dead_code)]
    exp: i64,
}

fn verify_admin_jwt(token: &str, secret: &[u8]) -> Option<Vec<String>> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    let data =
        decode::<AdminJwtClaims>(token, &DecodingKey::from_secret(secret), &validation).ok()?;
    Some(data.claims.scp)
}

fn jwt_auth_ok(scopes: &[String], method: &Method) -> bool {
    let scopes_l: Vec<String> = scopes.iter().map(|s| s.to_ascii_lowercase()).collect();
    if scopes_l
        .iter()
        .any(|s| s == "admin:super" || s == "*" || s == "admin:full")
    {
        return true;
    }
    let read_ok = method == Method::GET || method == Method::HEAD;
    if read_ok {
        scopes_l
            .iter()
            .any(|s| s == "admin:read" || s == "admin:write")
    } else {
        scopes_l.iter().any(|s| s == "admin:write")
    }
}

fn key_matches_any(candidate: &[u8], keys: &[Vec<u8>]) -> bool {
    keys.iter().any(|k| {
        if k.len() != candidate.len() {
            return false;
        }
        k.as_slice().ct_eq(candidate).into()
    })
}

fn extract_bearer_token(request: &Request) -> Option<String> {
    let h = request.headers().get(AUTHORIZATION)?.to_str().ok()?.trim();
    let rest = h
        .strip_prefix("Bearer ")
        .or_else(|| h.strip_prefix("bearer "))?
        .trim();
    if rest.is_empty() {
        return None;
    }
    Some(rest.to_string())
}

fn extract_x_admin_key_bytes(request: &Request) -> Vec<u8> {
    request
        .headers()
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .as_bytes()
        .to_vec()
}

pub async fn auth_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let cfg = admin_cfg();
    let method = request.method().clone();

    if let Some(token) = extract_bearer_token(&request) {
        if let Some(ref sec) = cfg.jwt_hs256_secret {
            if let Some(scopes) = verify_admin_jwt(&token, sec) {
                if jwt_auth_ok(&scopes, &method) {
                    return Ok(next.run(request).await);
                }
                return Err(StatusCode::UNAUTHORIZED);
            }
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    let key_bytes = extract_x_admin_key_bytes(&request);
    if key_bytes.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if key_matches_any(&key_bytes, &cfg.full_write_keys) {
        return Ok(next.run(request).await);
    }
    if key_matches_any(&key_bytes, &cfg.read_only_keys) {
        if method == Method::GET || method == Method::HEAD {
            return Ok(next.run(request).await);
        }
        return Err(StatusCode::FORBIDDEN);
    }

    Err(StatusCode::UNAUTHORIZED)
}

// ─────────────────────────────────────────────────────
//  POST /admin/clients — créer un nouveau site partenaire
// ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddClientRequest {
    pub name: String,
    pub client_type: ClientType,
}

#[derive(Serialize)]
pub struct AddClientResponse {
    pub name: String,
    pub public_key_hex: String,
    pub key_image_hex: String,
    pub client_type: String,
}

pub async fn add_client(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<AddClientRequest>,
) -> Result<Json<AddClientResponse>, (StatusCode, String)> {
    // Génère une paire de clés Ristretto aléatoire pour ce site.
    let identity = Identity::random();
    let pub_hex = identity.public_hex();
    let priv_hex = identity.secret_hex();
    let ki_hex = identity.key_image_hex();
    let type_str = payload.client_type.as_db_str();

    // Persistance en DB.
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.execute(
            "INSERT INTO clients (name, public_key_hex, private_key_hex, key_image_hex, client_type)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![payload.name, pub_hex, priv_hex, ki_hex, type_str],
        ).map_err(|e| (StatusCode::CONFLICT, format!("Client already exists or DB error: {e}")))?;
    }

    // Ajouter la clé publique au groupe client en mémoire (pour vérifier les ring sigs Flux 1).
    {
        let mut st = state.write().unwrap();
        // pub_hex is server-generated via Identity::random() so decoding is
        // expected to succeed, but we defensively avoid panic on any future
        // refactor that pipes user-influenced hex through this path.
        let pub_bytes = hex::decode(&pub_hex)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("hex decode: {e}")))?;
        if let Some(pt) = CompressedRistretto::from_slice(&pub_bytes)
            .ok()
            .and_then(|c| c.decompress())
        {
            st.client_group.add_member(pt);
        }
        println!(
            "[ADMIN] New client '{}' ({}) added. client_group_size={}",
            payload.name,
            type_str,
            st.client_group.members.len()
        );
    }

    Ok(Json(AddClientResponse {
        name: payload.name,
        public_key_hex: pub_hex,
        key_image_hex: ki_hex,
        client_type: type_str.to_string(),
    }))
}

// ─────────────────────────────────────────────────────
//  GET /admin/users
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AdminUserRecord {
    pub key_image_hex: String,
    pub first_name: String,
    pub last_name: String,
    pub nationality: String,
}

/// GET /admin/anchor/agent-actions/proof?receipt_id=<rcp_…>
/// Return the merkle inclusion proof for an agent action receipt within the
/// batch that anchored it on Bitcoin (OTS) and Solana (Memo).
#[derive(Deserialize)]
pub struct ActionAnchorProofQuery {
    pub receipt_id: String,
}

pub async fn get_action_anchor_proof(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::extract::Query(q): axum::extract::Query<ActionAnchorProofQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match crate::agent_action_anchor::proof_for_receipt(&state, &q.receipt_id) {
        Ok(Some(v)) => Ok(Json(v)),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            "receipt_id not yet anchored (next anchor batch will include it)".into(),
        )),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

/// GET /admin/anchor/batches?limit=N — list recent anchor batches with the
/// per-chain three-state surface (ADR-001). Each row reports:
///
/// ```json
/// {
///   "anchor_id": "...",
///   "n_actions": 42,
///   "created_at": 1715800000,
///   "solana":  {"confirmed": true,  "slot": 12345, "sig": "..."},
///   "bitcoin": {"provider": "opentimestamps", "ots_upgraded": false, "block_height": null},
///   "anchored": false   // DEPRECATED — kept one minor version, see ADR-001
/// }
/// ```
///
/// The three UI states are computed client-side from the two booleans:
///   - "Pending"                          → !solana.confirmed
///   - "Solana-confirmed (BTC pending)"   →  solana.confirmed && !bitcoin.ots_upgraded
///   - "Dually anchored"                  →  solana.confirmed &&  bitcoin.ots_upgraded
#[derive(Deserialize)]
pub struct AnchorBatchesQuery {
    pub limit: Option<i64>,
}

pub async fn get_anchor_batches(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::extract::Query(q): axum::extract::Query<AnchorBatchesQuery>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    match crate::agent_action_anchor::recent_batches(&state, limit) {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

/// POST /admin/anchor/agent-actions/run
/// Force an immediate anchor batch instead of waiting for the periodic task.
/// Useful for tests and one-shot CI verification.
pub async fn force_action_anchor_run(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match crate::agent_action_anchor::anchor_pending_actions(&state).await {
        Ok(Some(anchor_id)) => Ok(Json(serde_json::json!({ "anchor_id": anchor_id }))),
        Ok(None) => Ok(Json(serde_json::json!({ "anchor_id": null, "reason": "no new receipts" }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

/// GET /health (public) — minimal liveness probe.
///
/// Returns ONLY `{ok: bool}`. Does not leak runtime mode, feature flags,
/// anchor configuration, or DB backend — those would be reconnaissance
/// information for an attacker. The detailed structured report lives at
/// `/admin/health/detailed` behind admin auth.
pub async fn health_public(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<serde_json::Value> {
    // Keep this trivial. Just check the DB roundtrip.
    let ok = {
        let st = state.read().unwrap();
        match st.db.lock() {
            Ok(conn) => conn
                .query_row("SELECT 1", [], |r| r.get::<_, i64>(0))
                .is_ok(),
            Err(_) => false,
        }
    };
    Json(serde_json::json!({ "ok": ok }))
}

/// GET /admin/health/detailed — structured health for operators.
///
/// Same shape as the previous public `/health`, but admin-gated so the
/// configuration surface isn't exposed to unauthenticated clients. Operators
/// scrape this from internal load balancers / monitoring agents.
#[derive(Serialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub runtime: &'static str,
    pub call_sig_enforce: bool,
    pub require_agent_type: bool,
    pub bitcoin_anchor: HealthComponent,
    pub solana_anchor: HealthComponent,
    pub database: HealthComponent,
    pub feature_flags: HealthFlags,
    pub warnings: Vec<String>,
}

#[derive(Serialize, Default)]
pub struct HealthComponent {
    pub ok: bool,
    pub detail: String,
}

#[derive(Serialize)]
pub struct HealthFlags {
    pub bank_kyc_enabled: bool,
    pub user_kyc_enabled: bool,
    pub zkp_issuer_enabled: bool,
    pub compliance_enabled: bool,
}

pub async fn health(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<HealthResponse> {
    let runtime = if crate::runtime_mode::is_development_runtime() {
        "development"
    } else {
        "production"
    };

    let flag = |name: &str| -> bool {
        match std::env::var(name).ok() {
            Some(v) => {
                let low = v.to_ascii_lowercase();
                v == "1" || low == "true" || low == "yes"
            }
            None => false,
        }
    };

    let call_sig_enforce = match std::env::var("SAURON_REQUIRE_CALL_SIG").ok() {
        Some(v) => {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        }
        None => !crate::runtime_mode::is_development_runtime(),
    };
    let require_agent_type = match std::env::var("SAURON_REQUIRE_AGENT_TYPE").ok() {
        Some(v) => {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        }
        None => !crate::runtime_mode::is_development_runtime(),
    };

    let mut warnings: Vec<String> = Vec::new();

    // Bitcoin anchor health
    let bitcoin_anchor = match state.read().unwrap().bitcoin_anchor.as_ref() {
        Some(svc) => HealthComponent {
            ok: true,
            detail: format!("provider={:?}", svc.provider()),
        },
        None => {
            warnings.push("Bitcoin anchor disabled — audit log is not externally verifiable on BTC".into());
            HealthComponent { ok: false, detail: "disabled".into() }
        }
    };
    let solana_anchor = match state.read().unwrap().solana_anchor.as_ref() {
        Some(svc) => HealthComponent {
            ok: true,
            detail: format!("signer={}", &svc.signer_pubkey_b58()[..20]),
        },
        None => {
            warnings.push("Solana anchor disabled — audit log is not externally verifiable on Solana".into());
            HealthComponent { ok: false, detail: "disabled (set SAURON_SOLANA_ENABLED=1)".into() }
        }
    };

    // DB roundtrip
    let database = {
        let st = state.read().unwrap();
        match st.db.lock() {
            Ok(conn) => match conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0)) {
                Ok(_) => HealthComponent { ok: true, detail: "sqlite".into() },
                Err(e) => HealthComponent { ok: false, detail: format!("sqlite query failed: {e}") },
            },
            Err(e) => HealthComponent { ok: false, detail: format!("db lock: {e}") },
        }
    };

    let feature_flags = HealthFlags {
        bank_kyc_enabled: crate::feature_flags::bank_kyc_enabled(),
        user_kyc_enabled: crate::feature_flags::user_kyc_enabled(),
        zkp_issuer_enabled: crate::feature_flags::zkp_issuer_enabled(),
        compliance_enabled: crate::feature_flags::compliance_enabled(),
    };

    if runtime == "production" && !call_sig_enforce {
        warnings.push("Production runtime but SAURON_REQUIRE_CALL_SIG is not enforced — per-call signature is advisory only".into());
    }
    if runtime == "production" && !require_agent_type {
        warnings.push("Production runtime but SAURON_REQUIRE_AGENT_TYPE is off — operators can supply unverified checksums".into());
    }
    if flag("SAURON_VAULT_TRANSIT_ENABLED") == false && runtime == "production" {
        warnings.push("Production runtime but Vault Transit is not enabled — root secrets in plain env".into());
    }

    let ok = database.ok && warnings.is_empty();

    Json(HealthResponse {
        ok,
        runtime,
        call_sig_enforce,
        require_agent_type,
        bitcoin_anchor,
        solana_anchor,
        database,
        feature_flags,
        warnings,
    })
}

// ─────────────────────────────────────────────────────
//  Live-data admin endpoints (Analytics 5/5)
//
//  These replace the parquet path in data/sauron/app.py. Every dashboard
//  number now comes from a live SQL query against the SauronID core.
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AdminAgentRecord {
    pub agent_id: String,
    pub human_key_image: String,
    pub agent_checksum: String,
    pub assurance_level: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
    pub has_pop: bool,
    pub agent_type: String,
}

/// GET /admin/agents — list every registered agent + checksum + revocation status.
pub async fn get_agents(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<Vec<AdminAgentRecord>>, AppError> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT a.agent_id, a.human_key_image, a.agent_checksum, a.assurance_level,
                    a.issued_at, a.expires_at, a.revoked,
                    IFNULL(LENGTH(a.pop_public_key_b64u), 0),
                    IFNULL(ci.agent_type, '')
             FROM agents a
             LEFT JOIN agent_checksum_inputs ci ON ci.agent_id = a.agent_id
             ORDER BY a.issued_at DESC",
        )?;
    let records: Vec<AdminAgentRecord> = stmt
        .query_map([], |row| {
            let pop_len: i64 = row.get(7)?;
            Ok(AdminAgentRecord {
                agent_id: row.get(0)?,
                human_key_image: row.get(1)?,
                agent_checksum: row.get(2)?,
                assurance_level: row.get(3)?,
                issued_at: row.get(4)?,
                expires_at: row.get(5)?,
                revoked: row.get::<_, i64>(6)? != 0,
                has_pop: pop_len > 0,
                agent_type: row.get(8)?,
            })
        })?
        .flatten()
        .collect();
    Ok(Json(records))
}

#[derive(Serialize)]
pub struct AdminActionReceiptRecord {
    pub receipt_id: String,
    pub action_hash: String,
    pub agent_id: String,
    pub status: String,
    pub policy_version: String,
    pub created_at: i64,
}

/// GET /admin/agent_actions/recent?limit=N — last N agent action receipts.
pub async fn get_recent_actions(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::extract::Query(q): axum::extract::Query<RecentLimitQuery>,
) -> Result<Json<Vec<AdminActionReceiptRecord>>, AppError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT receipt_id, action_hash, agent_id, status, policy_version, created_at
             FROM agent_action_receipts
             ORDER BY created_at DESC
             LIMIT ?1",
        )?;
    let records: Vec<AdminActionReceiptRecord> = stmt
        .query_map(rusqlite::params![limit], |row| {
            Ok(AdminActionReceiptRecord {
                receipt_id: row.get(0)?,
                action_hash: row.get(1)?,
                agent_id: row.get(2)?,
                status: row.get(3)?,
                policy_version: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?
        .flatten()
        .collect();
    Ok(Json(records))
}

#[derive(Deserialize)]
pub struct RecentLimitQuery {
    pub limit: Option<i64>,
}

#[derive(Serialize, Default)]
pub struct AdminAnchorStatus {
    pub bitcoin_total: i64,
    pub bitcoin_pending_upgrade: i64,
    pub bitcoin_upgraded: i64,
    pub solana_total: i64,
    pub solana_unconfirmed: i64,
    pub solana_confirmed: i64,
    pub agent_action_batches: i64,
    pub last_batch_at: i64,
    pub last_batch_n_actions: i64,
}

/// GET /admin/anchor/status — current state of the on-chain anchor pipeline.
pub async fn get_anchor_status(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<AdminAnchorStatus> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut s = AdminAnchorStatus::default();
    s.bitcoin_total = db
        .query_row("SELECT COUNT(*) FROM bitcoin_merkle_anchors", [], |r| r.get(0))
        .unwrap_or(0);
    s.bitcoin_pending_upgrade = db
        .query_row(
            "SELECT COUNT(*) FROM bitcoin_merkle_anchors WHERE provider = 'opentimestamps' AND ots_upgraded = 0",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    s.bitcoin_upgraded = db
        .query_row(
            "SELECT COUNT(*) FROM bitcoin_merkle_anchors WHERE ots_upgraded = 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    s.solana_total = db
        .query_row("SELECT COUNT(*) FROM solana_merkle_anchors", [], |r| r.get(0))
        .unwrap_or(0);
    s.solana_unconfirmed = db
        .query_row(
            "SELECT COUNT(*) FROM solana_merkle_anchors WHERE confirmed = 0",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    s.solana_confirmed = db
        .query_row(
            "SELECT COUNT(*) FROM solana_merkle_anchors WHERE confirmed = 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    s.agent_action_batches = db
        .query_row("SELECT COUNT(*) FROM agent_action_anchors", [], |r| r.get(0))
        .unwrap_or(0);
    if let Ok(row) = db.query_row(
        "SELECT created_at, n_actions FROM agent_action_anchors ORDER BY created_at DESC LIMIT 1",
        [],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
    ) {
        s.last_batch_at = row.0;
        s.last_batch_n_actions = row.1;
    }
    Json(s)
}

#[derive(Serialize)]
pub struct AdminPerAgentMetric {
    pub agent_id: String,
    pub action_count: i64,
    pub egress_count: i64,
    pub last_action_at: i64,
}

/// GET /admin/per_agent_metrics?limit=N — per-agent action + egress counts, sorted by activity.
pub async fn get_per_agent_metrics(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::extract::Query(q): axum::extract::Query<RecentLimitQuery>,
) -> Result<Json<Vec<AdminPerAgentMetric>>, AppError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT a.agent_id,
                    (SELECT COUNT(*) FROM agent_action_receipts r WHERE r.agent_id = a.agent_id) AS act_count,
                    (SELECT COUNT(*) FROM agent_egress_log e WHERE e.agent_id = a.agent_id)      AS egress_count,
                    (SELECT IFNULL(MAX(created_at),0) FROM agent_action_receipts r WHERE r.agent_id = a.agent_id) AS last_at
             FROM agents a
             ORDER BY act_count DESC, egress_count DESC
             LIMIT ?1",
        )?;
    let records: Vec<AdminPerAgentMetric> = stmt
        .query_map(rusqlite::params![limit], |row| {
            Ok(AdminPerAgentMetric {
                agent_id: row.get(0)?,
                action_count: row.get(1)?,
                egress_count: row.get(2)?,
                last_action_at: row.get(3)?,
            })
        })?
        .flatten()
        .collect();
    Ok(Json(records))
}

#[derive(Serialize)]
pub struct AdminEgressEntry {
    pub id: i64,
    pub agent_id: String,
    pub target_host: String,
    pub target_path: String,
    pub method: String,
    pub status_code: i64,
    pub ts: i64,
    pub allowed: bool,
}

/// GET /admin/egress/recent?limit=N — recent agent egress events.
pub async fn get_recent_egress(
    State(state): State<Arc<RwLock<ServerState>>>,
    axum::extract::Query(q): axum::extract::Query<RecentLimitQuery>,
) -> Result<Json<Vec<AdminEgressEntry>>, AppError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT id, agent_id, target_host, target_path, method, status_code, ts, allowed
             FROM agent_egress_log
             ORDER BY ts DESC LIMIT ?1",
        )?;
    let records: Vec<AdminEgressEntry> = stmt
        .query_map(rusqlite::params![limit], |row| {
            Ok(AdminEgressEntry {
                id: row.get(0)?,
                agent_id: row.get(1)?,
                target_host: row.get(2)?,
                target_path: row.get(3)?,
                method: row.get(4)?,
                status_code: row.get(5)?,
                ts: row.get(6)?,
                allowed: row.get::<_, i64>(7)? != 0,
            })
        })?
        .flatten()
        .collect();
    Ok(Json(records))
}

/// GET /admin/checksum/audit/{agent_id} — every checksum rotation for an agent.
#[derive(Serialize)]
pub struct AdminChecksumAudit {
    pub from_checksum: String,
    pub to_checksum: String,
    pub reason: String,
    pub actor: String,
    pub ts: i64,
}

pub async fn get_checksum_audit(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(agent_id): Path<String>,
) -> Result<Json<Vec<AdminChecksumAudit>>, AppError> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT from_checksum, to_checksum, reason, actor, ts
             FROM agent_checksum_audit
             WHERE agent_id = ?1
             ORDER BY ts DESC",
        )?;
    let records: Vec<AdminChecksumAudit> = stmt
        .query_map(rusqlite::params![agent_id], |row| {
            Ok(AdminChecksumAudit {
                from_checksum: row.get(0)?,
                to_checksum: row.get(1)?,
                reason: row.get(2)?,
                actor: row.get(3)?,
                ts: row.get(4)?,
            })
        })?
        .flatten()
        .collect();
    Ok(Json(records))
}

pub async fn get_users(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<Vec<AdminUserRecord>>, AppError> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db
        .prepare("SELECT key_image_hex, first_name, last_name, nationality FROM users")?;
    let records: Vec<AdminUserRecord> = stmt
        .query_map([], |row| {
            Ok(AdminUserRecord {
                key_image_hex: row.get(0)?,
                first_name: row.get(1)?,
                last_name: row.get(2)?,
                nationality: row.get(3)?,
            })
        })?
        .flatten()
        .collect();
    Ok(Json(records))
}

// ─────────────────────────────────────────────────────
//  GET /admin/clients
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AdminClientRecord {
    pub name: String,
    pub public_key_hex: String,
    pub key_image_hex: String,
    pub tokens_b: i64,
    pub client_type: String,
}

pub async fn get_clients(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<Vec<AdminClientRecord>>, AppError> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT name, public_key_hex, key_image_hex, tokens_b, client_type FROM clients ORDER BY id"
    )?;
    let records: Vec<AdminClientRecord> = stmt
        .query_map([], |row| {
            Ok(AdminClientRecord {
                name: row.get(0)?,
                public_key_hex: row.get(1)?,
                key_image_hex: row.get(2)?,
                tokens_b: row.get(3)?,
                client_type: row.get(4)?,
            })
        })?
        .flatten()
        .collect();
    Ok(Json(records))
}

// ─────────────────────────────────────────────────────
//  GET /admin/site/:name/users — rétrocompabilité
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct SiteUserRecord {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub nationality: String,
    pub source: String,
    pub timestamp: i64,
}

pub async fn get_site_users(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(name): Path<String>,
) -> Result<Json<Vec<SiteUserRecord>>, AppError> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT u.first_name, u.last_name, u.email, u.nationality, r.source, r.timestamp
             FROM user_registrations r
             JOIN users u ON u.key_image_hex = r.user_key_image_hex
             WHERE r.client_name = ?1
             ORDER BY r.timestamp DESC
             LIMIT 500",
        )?;
    let records: Vec<SiteUserRecord> = stmt
        .query_map(params![name], |row| {
            Ok(SiteUserRecord {
                first_name: row.get(0)?,
                last_name: row.get(1)?,
                email: row.get(2)?,
                nationality: row.get(3)?,
                source: row.get(4)?,
                timestamp: row.get(5)?,
            })
        })?
        .flatten()
        .collect();
    Ok(Json(records))
}

// ─────────────────────────────────────────────────────
//  GET /admin/site/:name/zkp_proofs
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct SiteZkpProofRecord {
    pub id: i64,
    pub timestamp: i64,
    pub ring_size: u64,
    pub proved_claims: Vec<String>,
    pub raw_detail: String,
}

pub async fn get_site_zkp_proofs(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(name): Path<String>,
) -> Result<Json<Vec<SiteZkpProofRecord>>, AppError> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let pattern = format!("site={} %", name);
    let mut stmt = db
        .prepare(
            "SELECT id, timestamp, detail FROM requests_log \
         WHERE action_type = 'ZKP_VERIFY' AND status = 'OK' AND detail LIKE ?1 \
         ORDER BY id DESC LIMIT 200",
        )?;
    let records: Vec<SiteZkpProofRecord> = stmt
        .query_map(rusqlite::params![pattern], |row| {
            let id: i64 = row.get(0)?;
            let ts: i64 = row.get(1)?;
            let detail: String = row.get(2)?;
            Ok((id, ts, detail))
        })?
        .flatten()
        .map(|(id, timestamp, detail)| {
            // detail = "site=Discord ring=5 claims=age≥18,nationality:FRA"
            let mut ring_size: u64 = 0;
            let mut proved_claims: Vec<String> = vec![];
            for part in detail.split_whitespace() {
                if let Some(v) = part.strip_prefix("ring=") {
                    ring_size = v.parse().unwrap_or(0);
                } else if let Some(v) = part.strip_prefix("claims=") {
                    proved_claims = v.split(',').map(|s| s.to_string()).collect();
                }
            }
            if proved_claims.is_empty() {
                proved_claims.push("registered_user".to_string());
            }
            SiteZkpProofRecord {
                id,
                timestamp,
                ring_size,
                proved_claims,
                raw_detail: detail,
            }
        })
        .collect();
    Ok(Json(records))
}

// ─────────────────────────────────────────────────────
//  GET /admin/requests
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct RequestLogRecord {
    pub id: i64,
    pub timestamp: i64,
    pub action_type: String,
    pub status: String,
    pub detail: String,
}

pub async fn get_requests(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Result<Json<Vec<RequestLogRecord>>, AppError> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT id, timestamp, action_type, status, detail FROM requests_log ORDER BY id DESC LIMIT 200"
    )?;
    let records: Vec<RequestLogRecord> = stmt
        .query_map([], |row| {
            Ok(RequestLogRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                action_type: row.get(2)?,
                status: row.get(3)?,
                detail: row.get(4)?,
            })
        })?
        .flatten()
        .collect();
    Ok(Json(records))
}

// ─────────────────────────────────────────────────────
//  GET /admin/stats
// ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct StatsResponse {
    pub total_users: i64,
    pub total_clients: i64,
    pub total_api_calls: i64,
    pub total_kyc_retrievals: i64,
    pub total_agent_calls: i64,
    pub total_tokens_b_issued: i64,
    pub total_tokens_b_spent: i64,
    pub exchange_rate: i64,
    /// Operator-facing snapshot (no end-user PII): compliance, screening, issuer circuits, risk window.
    pub controls: serde_json::Value,
}

pub async fn get_stats(State(state): State<Arc<RwLock<ServerState>>>) -> Json<StatsResponse> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();

    let total_users: i64 = db
        .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
        .unwrap_or(0);
    let total_clients: i64 = db
        .query_row("SELECT COUNT(*) FROM clients", [], |r| r.get(0))
        .unwrap_or(0);
    let total_api_calls: i64 = db
        .query_row("SELECT COUNT(*) FROM api_usage", [], |r| r.get(0))
        .unwrap_or(0);
    let total_kyc_retrievals: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM api_usage WHERE action = 'kyc_human'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let total_agent_calls: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM api_usage WHERE is_agent = 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let total_tokens_b_spent: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM api_usage WHERE action IN ('kyc_human','kyc_agent','zkp_login')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let current_tokens_b: i64 = db
        .query_row("SELECT COALESCE(SUM(tokens_b), 0) FROM clients", [], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    let total_tokens_b_issued = current_tokens_b + total_tokens_b_spent;

    let controls = serde_json::json!({
        "compliance": st.compliance.admin_snapshot(),
        "screening": st.screening.admin_snapshot(),
        "issuer": st.issuer_runtime.circuit_snapshots_json(&st.issuer_urls),
        "risk": { "window_secs": risk::window_secs() },
    });

    Json(StatsResponse {
        total_users,
        total_clients,
        total_api_calls,
        total_kyc_retrievals,
        total_agent_calls,
        total_tokens_b_issued,
        total_tokens_b_spent,
        exchange_rate: 1,
        controls,
    })
}

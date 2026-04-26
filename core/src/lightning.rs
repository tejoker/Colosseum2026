use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Json,
};
use hmac::{Hmac, Mac};
use rusqlite::params;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ajwt_support::random_hex_32;
use crate::state::ServerState;

type HmacSha256 = Hmac<Sha256>;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn lightning_provider() -> String {
    std::env::var("SAURON_LIGHTNING_PROVIDER")
        .unwrap_or_else(|_| "mock".to_string())
        .trim()
        .to_ascii_lowercase()
}

fn l402_macaroon(secret: &[u8], invoice_id: &str, payment_hash: &str, agent_id: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key length");
    mac.update(b"L402|");
    mac.update(invoice_id.as_bytes());
    mac.update(b"|");
    mac.update(payment_hash.as_bytes());
    mac.update(b"|");
    mac.update(agent_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn payment_hash(preimage: &str) -> String {
    let mut h = Sha256::new();
    h.update(preimage.as_bytes());
    hex::encode(h.finalize())
}

#[derive(Deserialize)]
pub struct L402ChallengeBody {
    /// Authorization from `POST /agent/payment/authorize`.
    pub authorization_id: String,
    /// Paid service/resource being unlocked.
    pub service: String,
}

pub async fn create_l402_challenge(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<L402ChallengeBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if lightning_provider() != "mock" {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "Only SAURON_LIGHTNING_PROVIDER=mock is implemented; tests never move real sats".into(),
        ));
    }
    if payload.authorization_id.trim().is_empty() || payload.service.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "authorization_id and service are required".into()));
    }

    let now = now_secs();
    let (agent_id, amount_minor, currency, expires_at, consumed): (String, i64, String, i64, i64) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT agent_id, amount_minor, currency, expires_at, consumed
             FROM agent_payment_authorizations WHERE auth_id = ?1",
            params![payload.authorization_id.trim()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "payment authorization not found".to_string()))?
    };

    if consumed != 0 {
        return Err((StatusCode::CONFLICT, "payment authorization already consumed".into()));
    }
    if expires_at < now {
        return Err((StatusCode::GONE, "payment authorization expired".into()));
    }
    if currency != "SAT" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Lightning demo authorizations must use currency SAT".into(),
        ));
    }

    let invoice_id = format!("l402_{}", random_hex_32());
    let dev_payment_preimage = random_hex_32();
    let hash = payment_hash(&dev_payment_preimage);
    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let macaroon = l402_macaroon(&jwt_secret, &invoice_id, &hash, &agent_id);
    let amount_msat = amount_minor
        .checked_mul(1000)
        .ok_or((StatusCode::BAD_REQUEST, "amount too large".to_string()))?;
    let l402_expires_at = std::cmp::min(expires_at, now + 600);

    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.execute(
            "INSERT INTO lightning_l402_invoices
             (invoice_id, auth_id, agent_id, service, amount_msat, payment_hash, macaroon, settled, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9)",
            params![
                invoice_id,
                payload.authorization_id.trim(),
                agent_id,
                payload.service.trim(),
                amount_msat,
                hash,
                macaroon,
                now,
                l402_expires_at,
            ],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(Json(serde_json::json!({
        "status": 402,
        "provider": "mock",
        "network": "local-no-cost",
        "no_real_money": true,
        "invoice_id": invoice_id,
        "service": payload.service.trim(),
        "amount_msat": amount_msat,
        "amount_sat": amount_minor,
        "payment_hash": hash,
        "payment_request": format!("lnbc{}n1mock{}", amount_msat, &macaroon[..24]),
        "macaroon": macaroon,
        "dev_payment_preimage": dev_payment_preimage,
        "expires_at": l402_expires_at,
        "www_authenticate": format!("L402 macaroon=\"{}\", invoice=\"lnbc{}n1mock{}\"", macaroon, amount_msat, &macaroon[..24]),
    })))
}

#[derive(Deserialize)]
pub struct L402SettleBody {
    pub macaroon: String,
    pub preimage: String,
}

pub async fn settle_l402_mock(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<L402SettleBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if lightning_provider() != "mock" {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "Only SAURON_LIGHTNING_PROVIDER=mock is implemented; tests never move real sats".into(),
        ));
    }
    if payload.macaroon.trim().is_empty() || payload.preimage.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "macaroon and preimage are required".into()));
    }

    let now = now_secs();
    let preimage_hash = payment_hash(payload.preimage.trim());
    let (invoice_id, auth_id, agent_id, amount_msat, payment_hash_db, expires_at, settled): (
        String,
        String,
        String,
        i64,
        String,
        i64,
        i64,
    ) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT invoice_id, auth_id, agent_id, amount_msat, payment_hash, expires_at, settled
             FROM lightning_l402_invoices WHERE macaroon = ?1",
            params![payload.macaroon.trim()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
        )
        .map_err(|_| (StatusCode::UNAUTHORIZED, "unknown L402 macaroon".to_string()))?
    };

    if expires_at < now {
        return Err((StatusCode::GONE, "L402 invoice expired".into()));
    }
    if settled != 0 {
        return Ok(Json(serde_json::json!({
            "settled": true,
            "already_settled": true,
            "invoice_id": invoice_id,
            "authorization_id": auth_id,
            "agent_id": agent_id,
            "amount_msat": amount_msat,
            "provider": "mock",
            "no_real_money": true,
        })));
    }
    if preimage_hash != payment_hash_db {
        return Err((StatusCode::UNAUTHORIZED, "invalid mock payment preimage".into()));
    }

    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.execute(
            "UPDATE lightning_l402_invoices SET settled = 1 WHERE invoice_id = ?1",
            params![invoice_id],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(Json(serde_json::json!({
        "settled": true,
        "invoice_id": invoice_id,
        "authorization_id": auth_id,
        "agent_id": agent_id,
        "amount_msat": amount_msat,
        "provider": "mock",
        "no_real_money": true,
    })))
}

fn parse_l402_header(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get("authorization")?.to_str().ok()?.trim();
    let rest = raw
        .strip_prefix("L402 ")
        .or_else(|| raw.strip_prefix("l402 "))?
        .trim();
    let mut macaroon = "";
    let mut preimage = "";
    for part in rest.split(',') {
        let mut kv = part.trim().splitn(2, '=');
        let k = kv.next()?.trim();
        let v = kv.next()?.trim().trim_matches('"');
        if k == "macaroon" {
            macaroon = v;
        } else if k == "preimage" {
            preimage = v;
        }
    }
    if macaroon.is_empty() || preimage.is_empty() {
        None
    } else {
        Some((macaroon.to_string(), preimage.to_string()))
    }
}

pub async fn paid_agent_score(
    Path(agent_id): Path<String>,
    State(state): State<Arc<RwLock<ServerState>>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some((macaroon, preimage)) = parse_l402_header(&headers) else {
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            "Missing Authorization: L402 macaroon=\"...\", preimage=\"...\"".into(),
        ));
    };
    let preimage_hash = payment_hash(&preimage);
    let now = now_secs();

    let (invoice_agent_id, settled, payment_hash_db, expires_at, service, amount_msat): (
        String,
        i64,
        String,
        i64,
        String,
        i64,
    ) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT agent_id, settled, payment_hash, expires_at, service, amount_msat
             FROM lightning_l402_invoices WHERE macaroon = ?1",
            params![macaroon],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .map_err(|_| (StatusCode::PAYMENT_REQUIRED, "unknown L402 macaroon".to_string()))?
    };

    if invoice_agent_id != agent_id {
        return Err((StatusCode::FORBIDDEN, "L402 token is not bound to this agent".into()));
    }
    if settled == 0 {
        return Err((StatusCode::PAYMENT_REQUIRED, "L402 invoice is not settled".into()));
    }
    if expires_at < now {
        return Err((StatusCode::GONE, "L402 token expired".into()));
    }
    if preimage_hash != payment_hash_db {
        return Err((StatusCode::UNAUTHORIZED, "invalid payment preimage".into()));
    }

    Ok(Json(serde_json::json!({
        "agent_id": agent_id,
        "service": service,
        "trust_score": 92,
        "rating": "bounded-agent-payment-ready",
        "amount_msat_paid": amount_msat,
        "provider": "mock",
        "no_real_money": true,
        "evidence": [
            "agent-bound L402 token",
            "settled mock Lightning invoice",
            "payment preimage matches payment hash"
        ],
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Path;
    use crate::db;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn mock_payment_hash_matches_preimage() {
        let preimage = "dev-preimage";
        assert_eq!(payment_hash(preimage), payment_hash(preimage));
        assert_ne!(payment_hash(preimage), payment_hash("other"));
    }

    #[test]
    fn parses_l402_authorization_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "L402 macaroon=\"abc\", preimage=\"def\"".parse().unwrap(),
        );
        let parsed = parse_l402_header(&headers).unwrap();
        assert_eq!(parsed.0, "abc");
        assert_eq!(parsed.1, "def");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mock_l402_challenge_settle_and_unlock_flow() {
        let _guard = env_lock().lock().unwrap();
        let db_path = std::env::temp_dir().join(format!("sauron-l402-{}.db", random_hex_32()));
        std::env::set_var("DATABASE_PATH", db_path.to_string_lossy().to_string());
        std::env::set_var("SAURON_ENV", "local");
        std::env::set_var("SAURON_TOKEN_SECRET", "test-token-secret");
        std::env::set_var("SAURON_JWT_SECRET", "test-jwt-secret");
        std::env::set_var("SAURON_OPRF_SEED", "test-oprf-seed");
        std::env::set_var("SAURON_ISSUER_URL", "http://localhost:4000");
        std::env::set_var("SAURON_LIGHTNING_PROVIDER", "mock");

        let db_handle = Arc::new(db::open_db());
        let state = Arc::new(RwLock::new(ServerState::new(Arc::clone(&db_handle))));
        let auth_id = "auth_l402_test";
        let agent_id = "agent_l402_test";
        let now = now_secs();
        {
            let db = db_handle.lock().unwrap();
            db.execute(
                "INSERT INTO agent_payment_authorizations
                 (auth_id, agent_id, jti, amount_minor, currency, merchant_id, payment_ref, created_at, expires_at, consumed)
                 VALUES (?1, ?2, ?3, 2, 'SAT', 'merchant_l402_test', 'ref_l402_test', ?4, ?5, 0)",
                params![auth_id, agent_id, random_hex_32(), now, now + 300],
            )
            .unwrap();
        }

        let challenge = create_l402_challenge(
            State(Arc::clone(&state)),
            Json(L402ChallengeBody {
                authorization_id: auth_id.to_string(),
                service: "agent-score".to_string(),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(challenge["provider"], "mock");
        assert_eq!(challenge["no_real_money"], true);
        assert_eq!(challenge["amount_msat"], 2000);

        let macaroon = challenge["macaroon"].as_str().unwrap().to_string();
        let preimage = challenge["dev_payment_preimage"].as_str().unwrap().to_string();

        let mut locked_headers = HeaderMap::new();
        locked_headers.insert(
            "authorization",
            format!("L402 macaroon=\"{}\", preimage=\"{}\"", macaroon, preimage)
                .parse()
                .unwrap(),
        );
        let locked = paid_agent_score(
            Path(agent_id.to_string()),
            State(Arc::clone(&state)),
            locked_headers,
        )
        .await
        .unwrap_err();
        assert_eq!(locked.0, StatusCode::PAYMENT_REQUIRED);

        let settled = settle_l402_mock(
            State(Arc::clone(&state)),
            Json(L402SettleBody {
                macaroon: macaroon.clone(),
                preimage: preimage.clone(),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(settled["settled"], true);
        assert_eq!(settled["no_real_money"], true);

        let mut unlocked_headers = HeaderMap::new();
        unlocked_headers.insert(
            "authorization",
            format!("L402 macaroon=\"{}\", preimage=\"{}\"", macaroon, preimage)
                .parse()
                .unwrap(),
        );
        let unlocked = paid_agent_score(
            Path(agent_id.to_string()),
            State(Arc::clone(&state)),
            unlocked_headers,
        )
        .await
        .unwrap()
        .0;
        assert_eq!(unlocked["agent_id"], agent_id);
        assert_eq!(unlocked["service"], "agent-score");
        assert_eq!(unlocked["no_real_money"], true);

        drop(state);
        drop(db_handle);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    }
}

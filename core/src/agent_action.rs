use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use hmac::{Hmac, Mac};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};

use crate::{policy, ring, state::ServerState};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentActionEnvelope {
    pub agent_id: String,
    pub human_key_image: String,
    pub action: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub merchant_id: String,
    #[serde(default)]
    pub amount_minor: i64,
    #[serde(default)]
    pub currency: String,
    pub nonce: String,
    pub expires_at: i64,
    pub policy_hash: String,
    pub ajwt_jti: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentActionProof {
    pub envelope: AgentActionEnvelope,
    #[serde(alias = "agent_ring_signature")]
    pub ring_signature: ring::RingSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionReceipt {
    pub receipt_id: String,
    pub action_hash: String,
    pub agent_id: String,
    pub ring_key_image_hex: String,
    pub policy_version: String,
    pub ajwt_jti: String,
    pub pop_jkt: String,
    pub timestamp: i64,
    pub status: String,
    pub signature: String,
}

#[derive(Clone, Debug)]
pub struct AgentActionValidation {
    pub action_hash: String,
    pub ring_key_image_hex: String,
    pub receipt: ActionReceipt,
}

pub struct ValidateAgentActionOptions<'a> {
    pub agent_id: &'a str,
    pub human_key_image: &'a str,
    pub ajwt_jti: &'a str,
    pub intent: Option<&'a Value>,
    pub expected_action: &'a str,
    pub expected_resource: Option<&'a str>,
    pub expected_merchant_id: Option<&'a str>,
    pub expected_amount_minor: Option<i64>,
    pub expected_currency: Option<&'a str>,
    pub pop_jkt: Option<&'a str>,
    pub status: &'a str,
}

#[derive(Deserialize)]
pub struct AgentActionChallengeBody {
    pub agent_id: String,
    pub human_key_image: String,
    pub action: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub merchant_id: String,
    #[serde(default)]
    pub amount_minor: i64,
    #[serde(default)]
    pub currency: String,
    pub ajwt_jti: String,
    #[serde(default = "default_challenge_ttl_secs")]
    pub ttl_secs: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentActionChallengeResponse {
    pub envelope: AgentActionEnvelope,
    pub canonical: String,
    pub action_hash: String,
    pub agent_ring_public_keys_hex: Vec<String>,
    pub signer_index: usize,
    pub signing_public_key_hex: String,
}

#[derive(Deserialize)]
pub struct ReceiptVerifyBody {
    pub receipt: ActionReceipt,
}

fn default_challenge_ttl_secs() -> i64 {
    120
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// Fixed-field canonical JSON for action signatures. Do not replace with
/// `Value::to_string()`, because callers in other languages need byte parity.
pub fn canonical_envelope_json(envelope: &AgentActionEnvelope) -> String {
    format!(
        "{{\"agent_id\":{},\"human_key_image\":{},\"action\":{},\"resource\":{},\"merchant_id\":{},\"amount_minor\":{},\"currency\":{},\"nonce\":{},\"expires_at\":{},\"policy_hash\":{},\"ajwt_jti\":{}}}",
        json_str(&envelope.agent_id),
        json_str(&envelope.human_key_image),
        json_str(&envelope.action),
        json_str(&envelope.resource),
        json_str(&envelope.merchant_id),
        envelope.amount_minor,
        json_str(&envelope.currency),
        json_str(&envelope.nonce),
        envelope.expires_at,
        json_str(&envelope.policy_hash),
        json_str(&envelope.ajwt_jti),
    )
}

pub fn canonical_envelope_bytes(envelope: &AgentActionEnvelope) -> Vec<u8> {
    canonical_envelope_json(envelope).into_bytes()
}

pub fn action_hash(envelope: &AgentActionEnvelope) -> String {
    let mut h = Sha256::new();
    h.update(canonical_envelope_bytes(envelope));
    hex::encode(h.finalize())
}

pub fn expected_policy_hash(action: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"SAURON_AGENT_ACTION_POLICY|");
    h.update(policy::KYA_POLICY_MATRIX_VERSION.as_bytes());
    h.update(b"|");
    h.update(action.trim().as_bytes());
    hex::encode(h.finalize())
}

fn receipt_signing_payload(receipt: &ActionReceipt) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        receipt.receipt_id,
        receipt.action_hash,
        receipt.agent_id,
        receipt.ring_key_image_hex,
        receipt.policy_version,
        receipt.ajwt_jti,
        receipt.pop_jkt,
        receipt.timestamp,
        receipt.status,
    )
}

pub fn sign_receipt(jwt_secret: &[u8], receipt: &ActionReceipt) -> String {
    let mut mac = HmacSha256::new_from_slice(jwt_secret).expect("HMAC key length");
    mac.update(b"SAURON_AGENT_ACTION_RECEIPT|");
    mac.update(receipt_signing_payload(receipt).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_receipt_signature(jwt_secret: &[u8], receipt: &ActionReceipt) -> bool {
    use subtle::ConstantTimeEq;
    let expected = sign_receipt(jwt_secret, receipt);
    expected
        .as_bytes()
        .ct_eq(receipt.signature.as_bytes())
        .into()
}

fn action_allowed_by_intent(intent: Option<&Value>, expected_action: &str) -> bool {
    let Some(intent) = intent else {
        return false;
    };
    let expected = expected_action.trim().to_ascii_lowercase();
    if expected.is_empty() {
        return false;
    }
    let mut scopes: Vec<String> = Vec::new();
    if let Some(arr) = intent.get("scope").and_then(|v| v.as_array()) {
        scopes.extend(
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_ascii_lowercase()),
        );
    }
    if let Some(arr) = intent
        .get("constraints")
        .and_then(|v| v.get("scope"))
        .and_then(|v| v.as_array())
    {
        scopes.extend(
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_ascii_lowercase()),
        );
    }
    if let Some(action) = intent.get("action").and_then(|v| v.as_str()) {
        scopes.push(action.trim().to_ascii_lowercase());
    }
    scopes.iter().any(|s| s == &expected)
}

fn require_eq_str(label: &str, got: &str, expected: &str) -> Result<(), (StatusCode, String)> {
    if got != expected {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("agent_action envelope {label} mismatch"),
        ));
    }
    Ok(())
}

pub fn validate_agent_action(
    state: &Arc<RwLock<ServerState>>,
    proof: &AgentActionProof,
    opts: ValidateAgentActionOptions<'_>,
) -> Result<AgentActionValidation, (StatusCode, String)> {
    let env = &proof.envelope;
    require_eq_str("agent_id", &env.agent_id, opts.agent_id)?;
    require_eq_str(
        "human_key_image",
        &env.human_key_image,
        opts.human_key_image,
    )?;
    require_eq_str("action", &env.action, opts.expected_action)?;
    require_eq_str("ajwt_jti", &env.ajwt_jti, opts.ajwt_jti)?;
    if let Some(resource) = opts.expected_resource {
        require_eq_str("resource", &env.resource, resource)?;
    }
    if let Some(merchant_id) = opts.expected_merchant_id {
        require_eq_str("merchant_id", &env.merchant_id, merchant_id)?;
    }
    if let Some(amount_minor) = opts.expected_amount_minor {
        if env.amount_minor != amount_minor {
            return Err((
                StatusCode::UNAUTHORIZED,
                "agent_action envelope amount_minor mismatch".into(),
            ));
        }
    }
    if let Some(currency) = opts.expected_currency {
        require_eq_str("currency", &env.currency, currency)?;
    }
    if env.policy_hash != expected_policy_hash(opts.expected_action) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "agent_action policy_hash mismatch".into(),
        ));
    }
    if env.expires_at < now_secs() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "agent_action envelope expired".into(),
        ));
    }
    if env.nonce.trim().len() < 16 || env.nonce.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            "agent_action nonce must be 16..128 chars".into(),
        ));
    }
    if !action_allowed_by_intent(opts.intent, opts.expected_action) {
        return Err((
            StatusCode::FORBIDDEN,
            "A-JWT intent does not allow agent_action action".into(),
        ));
    }

    let canonical = canonical_envelope_bytes(env);
    let action_hash = action_hash(env);
    let ring_key_image_hex = hex::encode(proof.ring_signature.key_image.compress().as_bytes());
    let now = now_secs();

    let (receipt, ring_ok) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let (db_human, revoked, expires_at, public_key_hex, registered_key_image, pop_jkt): (
            String,
            i64,
            i64,
            String,
            String,
            String,
        ) = db
            .query_row(
                "SELECT human_key_image, revoked, expires_at, IFNULL(public_key_hex, ''), IFNULL(ring_key_image_hex, ''), IFNULL(pop_jkt, '')
                 FROM agents WHERE agent_id = ?1",
                params![opts.agent_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .map_err(|_| (StatusCode::NOT_FOUND, "Agent not found".to_string()))?;
        if db_human != opts.human_key_image || revoked != 0 || expires_at < now {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Agent revoked, expired, or owner mismatch".into(),
            ));
        }
        if public_key_hex.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Agent missing ring public key".into(),
            ));
        }
        if registered_key_image.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Agent missing registered ring key image".into(),
            ));
        }
        if registered_key_image != ring_key_image_hex {
            return Err((
                StatusCode::UNAUTHORIZED,
                "agent_action ring key image does not match registered agent".into(),
            ));
        }
        if let Some(expected_pop) = opts.pop_jkt {
            if !expected_pop.is_empty() && !pop_jkt.is_empty() && expected_pop != pop_jkt {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "agent_action PoP thumbprint mismatch".into(),
                ));
            }
        }

        let pk_bytes = hex::decode(&public_key_hex).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Agent public key encoding invalid".to_string(),
            )
        })?;
        let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Agent public key length invalid".to_string(),
            )
        })?;
        let pt = curve25519_dalek::ristretto::CompressedRistretto(pk_arr)
            .decompress()
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Agent public key point invalid".to_string(),
            ))?;
        if !st.agent_group.members.contains(&pt) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Agent public key is not in delegated ring".into(),
            ));
        }

        let ring_ok = ring::verify(&canonical, &st.agent_group.members, &proof.ring_signature);
        if ring_ok {
            db.execute(
                "DELETE FROM agent_action_nonces WHERE expires_at < ?1",
                params![now],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            db.execute(
                "INSERT INTO agent_action_nonces (nonce, agent_id, action_hash, expires_at, used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![env.nonce, opts.agent_id, action_hash, env.expires_at, now],
            )
            .map_err(|e| {
                if e.to_string().contains("UNIQUE") {
                    (StatusCode::UNAUTHORIZED, "agent_action nonce replay".to_string())
                } else {
                    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                }
            })?;
        }

        let mut receipt = ActionReceipt {
            receipt_id: format!("ar_{}", crate::ajwt_support::random_hex_32()),
            action_hash: action_hash.clone(),
            agent_id: opts.agent_id.to_string(),
            ring_key_image_hex: ring_key_image_hex.clone(),
            policy_version: policy::KYA_POLICY_MATRIX_VERSION.to_string(),
            ajwt_jti: opts.ajwt_jti.to_string(),
            pop_jkt: opts.pop_jkt.unwrap_or("").to_string(),
            timestamp: now,
            status: opts.status.to_string(),
            signature: String::new(),
        };
        receipt.signature = sign_receipt(&st.jwt_secret, &receipt);
        if ring_ok {
            db.execute(
                "INSERT OR REPLACE INTO agent_action_receipts
                 (receipt_id, action_hash, agent_id, ring_key_image_hex, policy_version, ajwt_jti, pop_jkt, status, signature, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    receipt.receipt_id,
                    receipt.action_hash,
                    receipt.agent_id,
                    receipt.ring_key_image_hex,
                    receipt.policy_version,
                    receipt.ajwt_jti,
                    receipt.pop_jkt,
                    receipt.status,
                    receipt.signature,
                    receipt.timestamp,
                ],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        (receipt, ring_ok)
    };

    if !ring_ok {
        return Err((
            StatusCode::UNAUTHORIZED,
            "agent_action ring signature verification failed".into(),
        ));
    }

    Ok(AgentActionValidation {
        action_hash,
        ring_key_image_hex,
        receipt,
    })
}

pub async fn action_challenge(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<AgentActionChallengeBody>,
) -> Result<Json<AgentActionChallengeResponse>, (StatusCode, String)> {
    if payload.agent_id.trim().is_empty()
        || payload.human_key_image.trim().is_empty()
        || payload.action.trim().is_empty()
        || payload.ajwt_jti.trim().is_empty()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "agent_id, human_key_image, action and ajwt_jti are required".into(),
        ));
    }
    let ttl = payload.ttl_secs.clamp(15, 300);
    let now = now_secs();
    let (agent_ring_public_keys_hex, signer_index, signing_public_key_hex) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let signing_public_key_hex: String = db
            .query_row(
                "SELECT IFNULL(public_key_hex, '') FROM agents WHERE agent_id = ?1 AND human_key_image = ?2 AND revoked = 0 AND expires_at > ?3",
                params![payload.agent_id, payload.human_key_image, now],
                |r| r.get(0),
            )
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "Agent not active for requested human".to_string(),
                )
            })?;
        if signing_public_key_hex.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Agent missing ring public key".into(),
            ));
        }
        let pk_bytes = hex::decode(&signing_public_key_hex).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Agent public key encoding invalid".to_string(),
            )
        })?;
        let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Agent public key length invalid".to_string(),
            )
        })?;
        let signing_point = curve25519_dalek::ristretto::CompressedRistretto(pk_arr)
            .decompress()
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Agent public key point invalid".to_string(),
            ))?;
        let signer_index = st
            .agent_group
            .members
            .iter()
            .position(|p| p == &signing_point)
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Agent public key is not in delegated ring".to_string(),
            ))?;
        let agent_ring_public_keys_hex = st
            .agent_group
            .members
            .iter()
            .map(|p| hex::encode(p.compress().as_bytes()))
            .collect();
        (
            agent_ring_public_keys_hex,
            signer_index,
            signing_public_key_hex,
        )
    };
    let envelope = AgentActionEnvelope {
        agent_id: payload.agent_id,
        human_key_image: payload.human_key_image,
        action: payload.action.trim().to_string(),
        resource: payload.resource,
        merchant_id: payload.merchant_id,
        amount_minor: payload.amount_minor,
        currency: payload.currency.trim().to_ascii_uppercase(),
        nonce: format!("aan_{}", crate::ajwt_support::random_hex_32()),
        expires_at: now + ttl,
        policy_hash: expected_policy_hash(payload.action.trim()),
        ajwt_jti: payload.ajwt_jti,
    };
    let canonical = canonical_envelope_json(&envelope);
    let action_hash = action_hash(&envelope);
    Ok(Json(AgentActionChallengeResponse {
        envelope,
        canonical,
        action_hash,
        agent_ring_public_keys_hex,
        signer_index,
        signing_public_key_hex,
    }))
}

pub async fn receipt_verify(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<ReceiptVerifyBody>,
) -> Json<Value> {
    let st = state.read().unwrap();
    let valid_sig = verify_receipt_signature(&st.jwt_secret, &payload.receipt);
    let db_seen: bool = {
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT COUNT(*) FROM agent_action_receipts WHERE receipt_id = ?1 AND action_hash = ?2 AND signature = ?3",
            params![
                payload.receipt.receipt_id,
                payload.receipt.action_hash,
                payload.receipt.signature
            ],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
            > 0
    };
    Json(serde_json::json!({
        "valid": valid_sig && db_seen,
        "signature_valid": valid_sig,
        "stored": db_seen,
        "action_hash": payload.receipt.action_hash,
        "agent_id": payload.receipt.agent_id,
        "policy_version": payload.receipt.policy_version,
        "status": payload.receipt.status,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_env() -> AgentActionEnvelope {
        AgentActionEnvelope {
            agent_id: "agt_1".into(),
            human_key_image: "human".into(),
            action: "payment_initiation".into(),
            resource: "payref".into(),
            merchant_id: "merchant".into(),
            amount_minor: 123,
            currency: "EUR".into(),
            nonce: "nonce-1234567890".into(),
            expires_at: 123456,
            policy_hash: expected_policy_hash("payment_initiation"),
            ajwt_jti: "jti".into(),
        }
    }

    #[test]
    fn canonical_envelope_is_stable_and_ordered() {
        let env = sample_env();
        assert_eq!(
            canonical_envelope_json(&env),
            format!(
                "{{\"agent_id\":\"agt_1\",\"human_key_image\":\"human\",\"action\":\"payment_initiation\",\"resource\":\"payref\",\"merchant_id\":\"merchant\",\"amount_minor\":123,\"currency\":\"EUR\",\"nonce\":\"nonce-1234567890\",\"expires_at\":123456,\"policy_hash\":\"{}\",\"ajwt_jti\":\"jti\"}}",
                env.policy_hash
            )
        );
    }

    #[test]
    fn changed_envelope_changes_action_hash() {
        let mut env = sample_env();
        let h1 = action_hash(&env);
        env.amount_minor += 1;
        assert_ne!(h1, action_hash(&env));
    }

    #[test]
    fn ring_signature_is_bound_to_exact_canonical_envelope() {
        let signer = crate::identity::Identity::random();
        let decoy = crate::identity::Identity::random();
        let ring_members = vec![signer.public, decoy.public];

        let env = sample_env();
        let msg = canonical_envelope_bytes(&env);
        let sig = ring::sign(&msg, &ring_members, &signer, 0);
        assert!(ring::verify(&msg, &ring_members, &sig));

        let mut changed = env.clone();
        changed.amount_minor += 1;
        assert!(!ring::verify(
            &canonical_envelope_bytes(&changed),
            &ring_members,
            &sig
        ));
    }

    #[test]
    fn ring_signature_rejects_secret_not_matching_ring_member() {
        let listed = crate::identity::Identity::random();
        let decoy = crate::identity::Identity::random();
        let outsider = crate::identity::Identity::random();
        let ring_members = vec![listed.public, decoy.public];

        let msg = canonical_envelope_bytes(&sample_env());
        let sig = ring::sign(&msg, &ring_members, &outsider, 0);
        assert!(!ring::verify(&msg, &ring_members, &sig));
    }

    #[test]
    fn receipt_signature_detects_tampering() {
        let mut r = ActionReceipt {
            receipt_id: "ar_1".into(),
            action_hash: "hash".into(),
            agent_id: "agt".into(),
            ring_key_image_hex: "ki".into(),
            policy_version: policy::KYA_POLICY_MATRIX_VERSION.into(),
            ajwt_jti: "jti".into(),
            pop_jkt: "jkt".into(),
            timestamp: 1,
            status: "accepted".into(),
            signature: String::new(),
        };
        let secret = b"01234567890123456789012345678901";
        r.signature = sign_receipt(secret, &r);
        assert!(verify_receipt_signature(secret, &r));
        r.status = "changed".into();
        assert!(!verify_receipt_signature(secret, &r));
    }

    #[test]
    fn challenge_response_serializes_signer_metadata() {
        let env = sample_env();
        let response = AgentActionChallengeResponse {
            canonical: canonical_envelope_json(&env),
            action_hash: action_hash(&env),
            envelope: env,
            agent_ring_public_keys_hex: vec!["aa".repeat(32), "bb".repeat(32)],
            signer_index: 1,
            signing_public_key_hex: "bb".repeat(32),
        };
        let encoded = serde_json::to_value(&response).unwrap();
        assert_eq!(encoded["signer_index"].as_u64(), Some(1));
        assert_eq!(
            encoded["signing_public_key_hex"].as_str().unwrap(),
            "bb".repeat(32)
        );
        assert_eq!(
            encoded["agent_ring_public_keys_hex"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}

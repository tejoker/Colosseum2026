// ─────────────────────────────────────────────────────────────────────────────
//  A-JWT Agentic Layer
//
//  An A-JWT (Agentic JSON Web Token) allows an AI agent to call the Sauron API
//  on behalf of a human user.  The token proves:
//    - Which human authorised the agent  (sub = human key_image_hex)
//    - What the agent is allowed to do   (intent JSON)
//    - The agent hasn't been tampered    (agent_checksum = SHA-256 of agent config)
//
//  Token format (EdDSA/Ed25519, base64url-encoded JSON parts):
//    header.payload.signature   (dot-separated, all base64url-no-padding)
//
//  Signing keys are derived per-agent from server secret + agent identity
//  material, so each agent has a distinct effective signing key.
// ─────────────────────────────────────────────────────────────────────────────

use crate::ajwt_support;
use crate::policy;
use crate::risk;
use crate::state::ServerState;
use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

// ─── Token helpers ───────────────────────────────────────────────────────────

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn verify_user_session(jwt_secret: &[u8], session: &str) -> Option<String> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let pos = session.rfind('|')?;
    let payload = &session[..pos];
    let sig = &session[pos + 1..];
    let mut mac = HmacSha256::new_from_slice(jwt_secret).ok()?;
    mac.update(b"|SESSION|");
    mac.update(payload.as_bytes());
    let computed = hex::encode(mac.finalize().into_bytes());
    if computed.as_bytes().ct_eq(sig.as_bytes()).unwrap_u8() == 0 {
        return None;
    }
    let pos2 = payload.rfind('|')?;
    let expires_at: i64 = payload[pos2 + 1..].parse().ok()?;
    if now_secs() > expires_at {
        return None;
    }
    Some(payload[..pos2].to_string())
}

fn session_key_image(headers: &HeaderMap, jwt_secret: &[u8]) -> Option<String> {
    let session = headers.get("x-sauron-session")?.to_str().ok()?;
    verify_user_session(jwt_secret, session)
}

/// Encode a JSON value as base64url (no padding).
fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

fn derive_agent_signing_key(
    jwt_secret: &[u8],
    agent_id: &str,
    human_key_image: &str,
    agent_checksum: &str,
) -> SigningKey {
    let mut h = Sha256::new();
    h.update(jwt_secret);
    h.update(b"|AJWT_ED25519|\n");
    h.update(agent_id.as_bytes());
    h.update(b"|");
    h.update(human_key_image.as_bytes());
    h.update(b"|");
    h.update(agent_checksum.as_bytes());
    let seed: [u8; 32] = h.finalize().into();
    SigningKey::from_bytes(&seed)
}

/// Optional claims aligned with `@sauronid/agentic` (cnf, workflow, delegation_chain).
#[derive(Clone, Default, Debug)]
pub struct AjwtExtraClaims {
    pub cnf_jkt: Option<String>,
    pub workflow_id: Option<String>,
    pub delegation_chain: Option<serde_json::Value>,
}

/// Forge an A-JWT signed with per-agent Ed25519 key material.
///
/// `intent` claim is always a **JSON string** (wire format). Optional `extra` adds
/// `cnf`, `workflow_id`, `delegation_chain` for client/server contract parity.
pub fn forge_ajwt(
    jwt_secret: &[u8],
    human_key_image: &str,
    agent_id: &str,
    agent_checksum: &str,
    intent_json: &str,
    ttl_secs: i64,
    extra: Option<&AjwtExtraClaims>,
) -> String {
    let header_obj = serde_json::json!({
        "alg": "EdDSA",
        "typ": "ajwt+jwt",
        "kid": agent_id,
    });
    let header = b64url(header_obj.to_string().as_bytes());
    let now = now_secs();
    let mut payload_obj = serde_json::json!({
        "iss": "did:sauron:idp",
        "sub": human_key_image,
        "agent_id": agent_id,
        "agent_checksum": agent_checksum,
        "intent": intent_json,
        "iat": now,
        "exp": now + ttl_secs,
        "jti": uuid_v4(),
    });
    if let Some(ex) = extra {
        if let Some(ref jkt) = ex.cnf_jkt {
            if !jkt.is_empty() {
                payload_obj["cnf"] = serde_json::json!({ "jkt": jkt });
            }
        }
        if let Some(ref wf) = ex.workflow_id {
            if !wf.is_empty() {
                payload_obj["workflow_id"] = serde_json::json!(wf);
            }
        }
        if let Some(ref dc) = ex.delegation_chain {
            payload_obj["delegation_chain"] = dc.clone();
        }
    }
    let payload = b64url(payload_obj.to_string().as_bytes());
    let signing_input = format!("{}.{}", header, payload);

    let signing_key =
        derive_agent_signing_key(jwt_secret, agent_id, human_key_image, agent_checksum);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let sig = b64url(&signature.to_bytes());
    format!("{}.{}.{}", header, payload, sig)
}

/// Verify an A-JWT.  Returns the decoded payload if valid.
pub fn verify_ajwt(jwt_secret: &[u8], token: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }

    let header_bytes = b64url_decode(parts[0])?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    if header.get("alg")?.as_str()? != "EdDSA" {
        return None;
    }

    let payload_bytes = b64url_decode(parts[1])?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

    let agent_id = payload.get("agent_id")?.as_str()?;
    let human_key_image = payload.get("sub")?.as_str()?;
    let agent_checksum = payload.get("agent_checksum")?.as_str()?;

    let signing_key =
        derive_agent_signing_key(jwt_secret, agent_id, human_key_image, agent_checksum);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let sig_bytes = b64url_decode(parts[2])?;
    let signature = Signature::from_slice(&sig_bytes).ok()?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .ok()?;

    // Check expiry
    let exp = payload.get("exp")?.as_i64()?;
    if now_secs() > exp {
        return None;
    }

    Some(payload)
}

fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ─── Request / Response types ────────────────────────────────────────────────

/// POST /agent/register
#[derive(Deserialize)]
pub struct RegisterAgentRequest {
    /// key_image_hex of the human owner (optional legacy field; server trusts session).
    #[serde(default)]
    pub human_key_image: String,
    /// SHA-256 hex of the agent's config (proves the agent is what it claims to be).
    /// Legacy compat: when `agent_type` + `checksum_inputs` are also provided, the
    /// server-computed value overrides this one and any mismatch is rejected.
    pub agent_checksum: String,
    /// Agent kind for typed checksum validation (llm | mcp_server | rule_bot | browser |
    /// openai_assistant | framework | custom). If absent, falls back to legacy
    /// operator-supplied `agent_checksum` with a warning logged.
    #[serde(default)]
    pub agent_type: String,
    /// Structured config object whose canonical SHA-256 becomes the binding checksum.
    /// Required fields per `agent_type` (e.g. llm: model_id, system_prompt, tools).
    /// Server validates and computes the canonical hash; operators cannot bypass.
    #[serde(default)]
    pub checksum_inputs: Option<serde_json::Value>,
    /// Optional hardware attestation blob (TPM2 quote / Nitro attestation / Apple
    /// Secure Enclave assertion). Stored verbatim; mitigates gap 3 (compromised host).
    #[serde(default)]
    pub attestation_blob: String,
    #[serde(default)]
    pub attestation_kind: String,
    /// JSON describing what the agent is allowed to do.
    #[serde(default = "default_intent")]
    pub intent_json: String,
    /// Agent public key (Ristretto compressed hex). Mandatory for ring membership.
    pub public_key_hex: String,
    /// Agent ring key image (Ristretto compressed hex). Mandatory for action-time leash binding.
    pub ring_key_image_hex: String,
    /// Lifetime in seconds (default 3600, max 86400).
    #[serde(default = "default_ttl")]
    pub ttl_secs: i64,
    /// If set, child agent: parent must exist, same human, and child scopes ⊆ parent intent.
    #[serde(default)]
    pub parent_agent_id: String,
    /// PoP JWK thumbprint (optional; if set with `pop_public_key_b64u`, consent may require PoP).
    #[serde(default)]
    pub pop_jkt: String,
    /// Ed25519 public key, 32-byte raw as base64url (optional).
    #[serde(default)]
    pub pop_public_key_b64u: String,
    #[serde(default)]
    pub workflow_id: String,
    /// JSON array/object string stored as `delegation_chain` claim in the A-JWT.
    #[serde(default)]
    pub delegation_chain_json: String,
    // ── M1 of TPM2-bound PoP key roadmap (docs/roadmap.md Plan 1) ────────
    // When `attestation_kind == "tpm2_quote"` all five tpm2_* fields are
    // required. The server stores them verbatim; verification is split:
    // M1 ships parsing (returns PartialImplementation), M2 ships the
    // cert-chain walker against TPM-vendor roots.
    #[serde(default)]
    pub tpm2_quote_b64: Option<String>,
    #[serde(default)]
    pub tpm2_attest_b64: Option<String>,
    #[serde(default)]
    pub tpm2_signature_b64: Option<String>,
    #[serde(default)]
    pub tpm2_aik_cert_pem: Option<String>,
    #[serde(default)]
    pub tpm2_ek_cert_chain_pem: Option<String>,
    /// JSON-encoded PCR selection + canonical hash the TPM2 quote is expected
    /// to bind. Stored verbatim in `agents.attestation_pcr_set`.
    #[serde(default)]
    pub tpm2_pcr_set: Option<String>,
    /// Base64url-encoded AIK public key. Stored verbatim in
    /// `agents.attestation_pubkey_b64u`. Once M2 lands, the verifier extracts
    /// this from the AIK cert directly — operators submitting it now make the
    /// transition seamless.
    #[serde(default)]
    pub tpm2_attestation_pubkey_b64u: Option<String>,
}

fn default_intent() -> String {
    "{}".to_string()
}
fn default_ttl() -> i64 {
    3600
}

#[derive(Serialize)]
pub struct RegisterAgentResponse {
    pub agent_id: String,
    pub ajwt: String,
    pub expires_at: i64,
    pub assurance_level: String,
}

/// POST /agent/token
#[derive(Deserialize)]
pub struct IssueAgentTokenRequest {
    pub agent_id: String,
    #[serde(default = "default_ttl")]
    pub ttl_secs: i64,
}

#[derive(Serialize)]
pub struct IssueAgentTokenResponse {
    pub agent_id: String,
    pub ajwt: String,
    pub expires_at: i64,
}

/// GET /agent/{agent_id}
#[derive(Serialize)]
pub struct AgentRecord {
    pub agent_id: String,
    pub human_key_image: String,
    pub agent_checksum: String,
    pub intent_json: String,
    pub assurance_level: String,
    pub ring_key_image_hex: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

/// POST /agent/verify  (used by external callers to validate an A-JWT)
#[derive(Deserialize)]
pub struct VerifyAjwtRequest {
    pub ajwt: String,
    /// If true, record `jti` server-side so the same token cannot be reused (e.g. before consent).
    #[serde(default)]
    pub consume_jti: bool,
    /// When the agent row has `pop_public_key_b64u`, same semantics as `/agent/kyc/consent` (challenge from `POST /agent/pop/challenge`).
    #[serde(default)]
    pub pop_challenge_id: String,
    #[serde(default)]
    pub pop_jws: String,
}

#[derive(Serialize)]
pub struct VerifyAjwtResponse {
    pub valid: bool,
    pub agent_id: Option<String>,
    pub human_key_image: Option<String>,
    pub intent_json: Option<String>,
    pub assurance_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn has_bank_kyc_link(db: &rusqlite::Connection, human_key_image: &str) -> bool {
    db.query_row(
        "SELECT COUNT(*) FROM bank_kyc_links WHERE user_key_image = ?1",
        params![human_key_image],
        |r| r.get::<_, i64>(0),
    )
    .ok()
    .unwrap_or(0)
        > 0
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// POST /agent/register — authenticated user registers an agent bound to their session.
pub async fn register_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    headers: HeaderMap,
    Json(mut payload): Json<RegisterAgentRequest>,
) -> Result<Json<RegisterAgentResponse>, (StatusCode, String)> {
    // ── Server-side checksum (Gap 4 fix) ──────────────────────────────────
    //
    // If the caller supplies typed `agent_type` + `checksum_inputs`, we
    // canonicalise + hash on the server. The resulting digest OVERRIDES any
    // operator-supplied `agent_checksum`. If the operator also passed a value
    // and it doesn't match, the registration is rejected — so a malicious
    // operator can't claim a different checksum than what the inputs hash to.
    //
    // Legacy path (no `agent_type`): operator-supplied `agent_checksum` accepted,
    // but a warning is logged. Existing tests pass through this path; new
    // deployments should always use typed inputs.
    // Determine whether legacy operator-supplied checksum is allowed.
    //
    // Rule: legacy mode is REJECTED in production-like runtimes by default.
    // Operators who need the legacy path during a migration can set
    // SAURON_REQUIRE_AGENT_TYPE=0 explicitly. In dev mode (ENV=development),
    // legacy mode is allowed with a warning so existing test scenarios keep
    // working without modification.
    let require_agent_type = match std::env::var("SAURON_REQUIRE_AGENT_TYPE").ok() {
        Some(v) => {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        }
        None => !crate::runtime_mode::is_development_runtime(),
    };

    let computed_checksum_pair: Option<(String, String, String)> = if !payload.agent_type.is_empty() {
        let inputs = payload
            .checksum_inputs
            .as_ref()
            .ok_or((
                StatusCode::BAD_REQUEST,
                "checksum_inputs required when agent_type is set".into(),
            ))?;
        let (canonical, computed) = crate::agent_checksum::compute_checksum(&payload.agent_type, inputs)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        if !payload.agent_checksum.is_empty() && payload.agent_checksum != computed {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "operator-supplied agent_checksum does not match server-computed value (expected {}, got {})",
                    computed, payload.agent_checksum
                ),
            ));
        }
        payload.agent_checksum = computed.clone();
        Some((payload.agent_type.clone(), canonical, computed))
    } else if require_agent_type {
        // Escape hatch fix: in production-like runtimes, refuse legacy operator-
        // supplied checksum. Forces operators to opt into the typed-input path
        // where the system prompt / model / tool list are server-bound.
        return Err((
            StatusCode::BAD_REQUEST,
            "agent_type + checksum_inputs are required (set SAURON_REQUIRE_AGENT_TYPE=0 to allow legacy operator-supplied agent_checksum, but be aware this disables runtime drift detection)".into(),
        ));
    } else {
        tracing::warn!(
            target: "sauron::agent_checksum",
            "agent registration with legacy operator-supplied checksum (no agent_type / checksum_inputs); recommend specifying agent_type for server-computed integrity"
        );
        None
    };

    if payload.agent_checksum.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_checksum required".into()));
    }
    if payload.public_key_hex.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "public_key_hex is required for delegated-agent ring binding".into(),
        ));
    }
    if !payload
        .ring_key_image_hex
        .chars()
        .all(|c| c.is_ascii_hexdigit())
        || payload.ring_key_image_hex.len() != 64
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "ring_key_image_hex is required and must be 32-byte hex".into(),
        ));
    }
    // ── M1 of TPM2-bound PoP key roadmap (docs/roadmap.md Plan 1) ────────
    //
    // 1. ServerDerived PoP: refuse in production unless explicitly opted in.
    //    The default-on behaviour is now opt-out — operators must set
    //    SAURON_ALLOW_SERVER_DERIVED_POP=1 OR run with ENV=development.
    //    Previously the server silently derived a PoP key from `jwt_secret`,
    //    making operator compromise = full agent impersonation. M1 makes the
    //    trust assumption explicit; M2 ships a TPM2-rooted alternative.
    //
    // 2. Tpm2Quote: all five tpm2_* payload fields are required when the
    //    operator advertises this kind. The server stores them verbatim;
    //    verification is M2.
    let kind_parsed = crate::attestation::AttestationKind::parse(&payload.attestation_kind);
    if matches!(kind_parsed, crate::attestation::AttestationKind::ServerDerived) {
        crate::attestation::check_server_derived_allowed().map_err(|e| {
            (StatusCode::FORBIDDEN, e.to_string())
        })?;
    }
    if matches!(kind_parsed, crate::attestation::AttestationKind::Tpm2Quote) {
        let missing: Vec<&'static str> = [
            ("tpm2_quote_b64", payload.tpm2_quote_b64.as_deref()),
            ("tpm2_attest_b64", payload.tpm2_attest_b64.as_deref()),
            ("tpm2_signature_b64", payload.tpm2_signature_b64.as_deref()),
            ("tpm2_aik_cert_pem", payload.tpm2_aik_cert_pem.as_deref()),
            (
                "tpm2_ek_cert_chain_pem",
                payload.tpm2_ek_cert_chain_pem.as_deref(),
            ),
        ]
        .into_iter()
        .filter_map(|(name, v)| match v {
            None => Some(name),
            Some(s) if s.trim().is_empty() => Some(name),
            _ => None,
        })
        .collect();
        if !missing.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "attestation_kind=tpm2_quote requires all five tpm2_* fields; missing: {}",
                    missing.join(", ")
                ),
            ));
        }

        // ── H2: bound size of TPM2 payload fields ────────────────────────────
        //
        // Without these guards a single registration request can ship 100s of
        // megabytes of PEM/base64 text, forcing the server to copy + persist
        // the whole blob before any verification runs. Cert-chain PEMs are
        // generous at 64 KiB (room for ~5 intermediate certs); raw TPM2
        // quote/attest/signature blobs are well under 4 KiB in practice but we
        // allow 32 KiB to leave slack for future algorithms.
        const MAX_PEM_LEN: usize = 65_536; // 64 KiB per cert chain
        const MAX_B64_FIELD_LEN: usize = 32_768; // 32 KiB for quote/attest/signature/pubkey
        const MAX_PCR_SET_LEN: usize = 8_192; // 8 KiB JSON for PCR selection
        let bounded: [(&'static str, Option<&str>, usize); 7] = [
            (
                "tpm2_quote_b64",
                payload.tpm2_quote_b64.as_deref(),
                MAX_B64_FIELD_LEN,
            ),
            (
                "tpm2_attest_b64",
                payload.tpm2_attest_b64.as_deref(),
                MAX_B64_FIELD_LEN,
            ),
            (
                "tpm2_signature_b64",
                payload.tpm2_signature_b64.as_deref(),
                MAX_B64_FIELD_LEN,
            ),
            (
                "tpm2_aik_cert_pem",
                payload.tpm2_aik_cert_pem.as_deref(),
                MAX_PEM_LEN,
            ),
            (
                "tpm2_ek_cert_chain_pem",
                payload.tpm2_ek_cert_chain_pem.as_deref(),
                MAX_PEM_LEN,
            ),
            (
                "tpm2_attestation_pubkey_b64u",
                payload.tpm2_attestation_pubkey_b64u.as_deref(),
                MAX_B64_FIELD_LEN,
            ),
            (
                "tpm2_pcr_set",
                payload.tpm2_pcr_set.as_deref(),
                MAX_PCR_SET_LEN,
            ),
        ];
        for (name, val, max) in bounded {
            if let Some(s) = val {
                if s.len() > max {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("{name} exceeds {max} bytes (got {})", s.len()),
                    ));
                }
            }
        }
    }

    if payload.pop_jkt.trim().is_empty() || payload.pop_public_key_b64u.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "PoP is mandatory: pop_jkt and pop_public_key_b64u are required".into(),
        ));
    }

    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let human_key_image = session_key_image(&headers, &jwt_secret).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;

    if !payload.human_key_image.is_empty() && payload.human_key_image != human_key_image {
        return Err((
            StatusCode::UNAUTHORIZED,
            "human_key_image payload does not match authenticated session".into(),
        ));
    }

    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let now = crate::ajwt_support::now_secs();
        risk::check_and_increment(
            &db,
            &risk::bucket_agent_register(&human_key_image),
            now,
            risk::limit_agent_register(),
        )
        .map_err(|_| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                "Agent registration rate limit exceeded".into(),
            )
        })?;
    }

    let agent_point = {
        let bytes = hex::decode(&payload.public_key_hex).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "public_key_hex must be valid hex".into(),
            )
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "public_key_hex must be 32-byte compressed Ristretto point".into(),
            )
        })?;
        curve25519_dalek::ristretto::CompressedRistretto(arr)
            .decompress()
            .ok_or((
                StatusCode::BAD_REQUEST,
                "public_key_hex is not a valid Ristretto point".into(),
            ))?
    };

    // Ensure no active agent already uses this pubkey.
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let in_use: bool = db
            .query_row(
                "SELECT COUNT(*) FROM agents WHERE public_key_hex = ?1 AND revoked = 0",
                params![payload.public_key_hex],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;
        if in_use {
            return Err((
                StatusCode::CONFLICT,
                "public_key_hex already registered to an active agent".into(),
            ));
        }
        let key_image_in_use: bool = db
            .query_row(
                "SELECT COUNT(*) FROM agents WHERE ring_key_image_hex = ?1 AND revoked = 0",
                params![payload.ring_key_image_hex],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;
        if key_image_in_use {
            return Err((
                StatusCode::CONFLICT,
                "ring_key_image_hex already registered to an active agent".into(),
            ));
        }
    }

    // Validate human exists in DB
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let exists: bool = db
            .query_row(
                "SELECT COUNT(*) FROM users WHERE key_image_hex = ?1",
                params![human_key_image],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;
        if !exists {
            return Err((
                StatusCode::NOT_FOUND,
                "Human user not found — register the user first".into(),
            ));
        }
    }

    let has_bank_link = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        has_bank_kyc_link(&db, &human_key_image)
    };

    if !has_bank_link {
        return Err((
            StatusCode::FORBIDDEN,
            "Delegated registration requires bank-verified KYC link. Use /agent/vc/issue for non-bank agents.".into(),
        ));
    };

    let assurance_level = "delegated_bank".to_string();

    let (parent_opt, delegation_depth) = if payload.parent_agent_id.is_empty() {
        (None::<String>, 0i64)
    } else {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let row: Result<(String, String, i64, i64), rusqlite::Error> = db.query_row(
            "SELECT intent_json, human_key_image, COALESCE(delegation_depth, 0), revoked FROM agents WHERE agent_id = ?1",
            params![&payload.parent_agent_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        );
        let (p_intent, p_human, p_depth, p_rev) = row.map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "parent_agent_id not found".to_string(),
            )
        })?;
        if p_rev != 0 {
            return Err((StatusCode::BAD_REQUEST, "parent agent is revoked".into()));
        }
        if p_human != human_key_image {
            return Err((
                StatusCode::FORBIDDEN,
                "parent agent belongs to another user".into(),
            ));
        }
        ajwt_support::assert_child_scopes_subset_of_parent(&p_intent, &payload.intent_json)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let d = p_depth + 1;
        if d > policy::MAX_DELEGATION_DEPTH as i64 {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "delegation depth exceeds max {}",
                    policy::MAX_DELEGATION_DEPTH
                ),
            ));
        }
        (Some(payload.parent_agent_id.clone()), d)
    };

    let ttl = payload.ttl_secs.clamp(60, 86400);
    let now = now_secs();
    let expires_at = now + ttl;

    // Generate a deterministic-ish agent_id from checksum + timestamp
    let mut h = Sha256::new();
    h.update(payload.agent_checksum.as_bytes());
    h.update(human_key_image.as_bytes());
    h.update(now.to_le_bytes());
    let agent_id = format!("agt_{}", &hex::encode(h.finalize())[..24]);

    let delegation_chain: Option<serde_json::Value> =
        if payload.delegation_chain_json.trim().is_empty() {
            None
        } else {
            Some(
                serde_json::from_str(&payload.delegation_chain_json).map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("delegation_chain_json invalid JSON: {e}"),
                    )
                })?,
            )
        };

    let extra = AjwtExtraClaims {
        cnf_jkt: if payload.pop_jkt.is_empty() {
            None
        } else {
            Some(payload.pop_jkt.clone())
        },
        workflow_id: if payload.workflow_id.is_empty() {
            None
        } else {
            Some(payload.workflow_id.clone())
        },
        delegation_chain,
    };

    let ajwt = forge_ajwt(
        &jwt_secret,
        &human_key_image,
        &agent_id,
        &payload.agent_checksum,
        &payload.intent_json,
        ttl,
        Some(&extra),
    );

    // Persist agent in DB
    {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        // M1 of TPM2 PoP roadmap: persist the new hardware-attestation columns
        // alongside the legacy blob+kind. They are NULL for non-TPM2 kinds.
        let attestation_pubkey_b64u = payload
            .tpm2_attestation_pubkey_b64u
            .as_deref()
            .filter(|s| !s.is_empty());
        let attestation_pcr_set = payload
            .tpm2_pcr_set
            .as_deref()
            .filter(|s| !s.is_empty());
        let attestation_ek_cert_chain_pem = payload
            .tpm2_ek_cert_chain_pem
            .as_deref()
            .filter(|s| !s.is_empty());
        db.execute(
            "INSERT OR REPLACE INTO agents
             (agent_id, human_key_image, agent_checksum, intent_json, assurance_level, public_key_hex, ring_key_image_hex, issued_at, expires_at, revoked, parent_agent_id, delegation_depth, pop_jkt, pop_public_key_b64u, attestation_blob, attestation_kind, attestation_pubkey_b64u, attestation_pcr_set, attestation_ek_cert_chain_pem)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![
                agent_id,
                human_key_image,
                payload.agent_checksum,
                payload.intent_json,
                assurance_level,
                payload.public_key_hex,
                payload.ring_key_image_hex,
                now,
                expires_at,
                parent_opt,
                delegation_depth,
                payload.pop_jkt,
                payload.pop_public_key_b64u,
                if payload.attestation_blob.is_empty() { None } else { Some(&payload.attestation_blob) },
                payload.attestation_kind,
                attestation_pubkey_b64u,
                attestation_pcr_set,
                attestation_ek_cert_chain_pem,
            ],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        // Server-computed checksum: persist the structured inputs so future
        // /agent/{id}/checksum/update calls can audit the prior version.
        if let Some((kind, canonical, _)) = computed_checksum_pair.as_ref() {
            crate::agent_checksum::persist_inputs(&db, &agent_id, kind, canonical, &payload.agent_checksum, now)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        }
    }

    // Mandatory ring membership for delegated agents.
    {
        let mut st = state.write().unwrap();
        if !st.agent_group.members.contains(&agent_point) {
            st.agent_group.members.push(agent_point);
        }
    }

    {
        let st = state.read().unwrap();
        st.log("AGENT_REGISTER", "OK", &agent_id);
    }
    println!(
        "[AGENT] Registered agent_id={} human={}",
        agent_id,
        &human_key_image[..16]
    );

    Ok(Json(RegisterAgentResponse {
        agent_id,
        ajwt,
        expires_at,
        assurance_level,
    }))
}

/// POST /agent/token — mint a fresh one-use A-JWT for an existing active agent.
///
/// Action endpoints consume A-JWT `jti`s. Multi-step demos and integrations
/// should call this endpoint before each independent agent action instead of
/// replaying the token returned by `/agent/register`.
pub async fn issue_agent_token(
    State(state): State<Arc<RwLock<ServerState>>>,
    headers: HeaderMap,
    Json(payload): Json<IssueAgentTokenRequest>,
) -> Result<Json<IssueAgentTokenResponse>, (StatusCode, String)> {
    if payload.agent_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_id required".into()));
    }
    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let session_human = session_key_image(&headers, &jwt_secret).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;

    let now = now_secs();
    let (human_key_image, agent_checksum, intent_json, revoked, agent_expires_at, pop_jkt): (
        String,
        String,
        String,
        i64,
        i64,
        String,
    ) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT human_key_image, agent_checksum, intent_json, revoked, expires_at, IFNULL(pop_jkt, '')
             FROM agents WHERE agent_id = ?1",
            params![payload.agent_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "Agent not found".to_string()))?
    };

    if human_key_image != session_human {
        return Err((
            StatusCode::FORBIDDEN,
            "agent not owned by authenticated session".into(),
        ));
    }
    if revoked != 0 || agent_expires_at <= now {
        return Err((StatusCode::UNAUTHORIZED, "Agent revoked or expired".into()));
    }

    let max_ttl = (agent_expires_at - now).max(1);
    let ttl = payload.ttl_secs.clamp(15, 3600).min(max_ttl);
    let extra = AjwtExtraClaims {
        cnf_jkt: if pop_jkt.is_empty() {
            None
        } else {
            Some(pop_jkt)
        },
        workflow_id: None,
        delegation_chain: None,
    };
    let ajwt = forge_ajwt(
        &jwt_secret,
        &human_key_image,
        &payload.agent_id,
        &agent_checksum,
        &intent_json,
        ttl,
        Some(&extra),
    );

    Ok(Json(IssueAgentTokenResponse {
        agent_id: payload.agent_id,
        ajwt,
        expires_at: now + ttl,
    }))
}

/// POST /agent/{agent_id}/checksum/update — rotate the registered config.
///
/// Operator updates the agent's typed config (e.g. new system prompt, added tool).
/// Server recomputes the canonical SHA, updates `agent_checksum`, and appends to
/// `agent_checksum_audit`. After this call, the agent runtime must use the matching
/// `x-sauron-agent-config-digest` header on subsequent calls.
///
/// Authentication: requires the same human session that originally registered the agent.
#[derive(Deserialize)]
pub struct ChecksumUpdateRequest {
    pub agent_type: String,
    pub checksum_inputs: serde_json::Value,
    #[serde(default)]
    pub reason: String,
}

#[derive(Serialize)]
pub struct ChecksumUpdateResponse {
    pub agent_id: String,
    pub from_checksum: String,
    pub to_checksum: String,
    pub version: i64,
}

pub async fn update_agent_checksum(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ChecksumUpdateRequest>,
) -> Result<Json<ChecksumUpdateResponse>, (StatusCode, String)> {
    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let actor_human_ki = session_key_image(&headers, &jwt_secret).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;

    let (canonical, new_checksum) =
        crate::agent_checksum::compute_checksum(&payload.agent_type, &payload.checksum_inputs)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Verify the caller owns the agent (same human as registration).
    let owner_ki: String = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT human_key_image FROM agents WHERE agent_id = ?1 AND revoked = 0",
            params![agent_id],
            |r| r.get::<_, String>(0),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "agent not found or revoked".into()))?
    };
    if owner_ki != actor_human_ki {
        return Err((
            StatusCode::FORBIDDEN,
            "only the registering human can rotate this agent's checksum".into(),
        ));
    }

    let prev_checksum: String = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT agent_checksum FROM agents WHERE agent_id = ?1",
            params![agent_id],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or_default()
    };

    let now = ajwt_support::now_secs();
    let new_version = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        crate::agent_checksum::rotate_inputs(
            &db,
            &agent_id,
            &payload.agent_type,
            &canonical,
            &new_checksum,
            &payload.reason,
            &actor_human_ki,
            now,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    };

    tracing::info!(
        target: "sauron::agent_checksum",
        agent_id = %agent_id,
        from = %prev_checksum,
        to = %new_checksum,
        version = new_version,
        "agent checksum rotated"
    );

    Ok(Json(ChecksumUpdateResponse {
        agent_id,
        from_checksum: prev_checksum,
        to_checksum: new_checksum,
        version: new_version,
    }))
}

/// GET /agent/{agent_id} — retrieve agent info.
pub async fn get_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentRecord>, StatusCode> {
    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    db.query_row(
        "SELECT agent_id, human_key_image, agent_checksum, intent_json, assurance_level, IFNULL(ring_key_image_hex, ''), issued_at, expires_at, revoked
         FROM agents WHERE agent_id = ?1",
        params![agent_id],
        |row| Ok(AgentRecord {
            agent_id:        row.get(0)?,
            human_key_image: row.get(1)?,
            agent_checksum:  row.get(2)?,
            intent_json:     row.get(3)?,
            assurance_level: row.get(4)?,
            ring_key_image_hex: row.get(5)?,
            issued_at:       row.get(6)?,
            expires_at:      row.get(7)?,
            revoked:         row.get::<_, i64>(8)? != 0,
        }),
    ).map(Json).map_err(|_| StatusCode::NOT_FOUND)
}

/// DELETE /agent/{agent_id} — revoke an agent owned by authenticated user.
pub async fn revoke_agent(
    State(state): State<Arc<RwLock<ServerState>>>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let human_ki = session_key_image(&headers, &jwt_secret).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;

    let rows = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.execute(
            "UPDATE agents SET revoked = 1 WHERE agent_id = ?1 AND human_key_image = ?2",
            params![agent_id, human_ki],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    if rows == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Agent not found or not owned by this user".into(),
        ));
    }

    {
        let st = state.read().unwrap();
        st.log("AGENT_REVOKE", "OK", &agent_id);
    }
    println!("[AGENT] Revoked agent_id={}", agent_id);

    Ok(Json(
        serde_json::json!({ "revoked": true, "agent_id": agent_id }),
    ))
}

/// POST /agent/verify — validate an A-JWT token.
pub async fn verify_agent_token(
    State(state): State<Arc<RwLock<ServerState>>>,
    Json(payload): Json<VerifyAjwtRequest>,
) -> Json<VerifyAjwtResponse> {
    let jwt_secret = state.read().unwrap().jwt_secret.clone();

    let claims = match verify_ajwt(&jwt_secret, &payload.ajwt) {
        None => {
            return Json(VerifyAjwtResponse {
                valid: false,
                agent_id: None,
                human_key_image: None,
                intent_json: None,
                assurance_level: None,
                error: Some("Invalid or expired A-JWT".into()),
            })
        }
        Some(c) => c,
    };

    let agent_id = claims
        .get("agent_id")
        .and_then(|v| v.as_str())
        .map(String::from);
    let human_ki = claims.get("sub").and_then(|v| v.as_str()).map(String::from);
    let intent = match claims.get("intent") {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(v) => serde_json::to_string(v).ok(),
        None => None,
    };

    // Rate-limit per agent_id to prevent token enumeration / replay amplification.
    if let Some(ref aid) = agent_id {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let now = crate::ajwt_support::now_secs();
        if risk::check_and_increment(
            &db,
            &risk::bucket_agent_verify(aid),
            now,
            risk::limit_agent_verify(),
        )
        .is_err()
        {
            return Json(VerifyAjwtResponse {
                valid: false,
                agent_id,
                human_key_image: human_ki,
                intent_json: intent,
                assurance_level: None,
                error: Some("Rate limit exceeded for agent verification".into()),
            });
        }
    }

    // Cross-check with DB: agent must not be revoked
    let mut assurance_level: Option<String> = None;

    if let Some(ref aid) = agent_id {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        let row: Option<(i64, String, String)> = db
            .query_row(
                "SELECT revoked, assurance_level, IFNULL(pop_public_key_b64u, '') FROM agents WHERE agent_id = ?1",
                params![aid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .ok();
        let (revoked, db_assurance, pop_pk_b64u) =
            row.unwrap_or((1, "delegated_nonbank".to_string(), String::new())); // missing row → revoked
        assurance_level = Some(db_assurance.clone());
        if revoked != 0 {
            return Json(VerifyAjwtResponse {
                valid: false,
                agent_id,
                human_key_image: human_ki,
                intent_json: intent,
                assurance_level: Some(db_assurance),
                error: Some("Agent has been revoked".into()),
            });
        }
        if !pop_pk_b64u.is_empty() {
            if payload.pop_challenge_id.is_empty() || payload.pop_jws.is_empty() {
                return Json(VerifyAjwtResponse {
                    valid: false,
                    agent_id: agent_id.clone(),
                    human_key_image: human_ki.clone(),
                    intent_json: intent.clone(),
                    assurance_level: Some(db_assurance),
                    error: Some(
                        "Agent requires PoP: provide pop_challenge_id and pop_jws (see POST /agent/pop/challenge)"
                            .into(),
                    ),
                });
            }
            // TODO M2-callsite-sweep: sync take_pop_challenge is called from
            // inside a held MutexGuard<Connection>; converting to await would
            // require unwinding the surrounding sync match. The legacy path
            // wraps the SELECT+DELETE in BEGIN IMMEDIATE so SQLite races are
            // safe today. Repo::take_pop_challenge is the dual-backend entry
            // point once this handler is converted to fully async.
            let challenge_plain =
                match ajwt_support::take_pop_challenge(&db, &payload.pop_challenge_id, aid) {
                    Ok(c) => c,
                    Err(e) => {
                        return Json(VerifyAjwtResponse {
                            valid: false,
                            agent_id: agent_id.clone(),
                            human_key_image: human_ki.clone(),
                            intent_json: intent.clone(),
                            assurance_level: Some(db_assurance),
                            error: Some(e),
                        });
                    }
                };
            if let Err(e) = ajwt_support::verify_ed25519_pop_jws(
                &challenge_plain,
                &payload.pop_jws,
                &pop_pk_b64u,
            ) {
                return Json(VerifyAjwtResponse {
                    valid: false,
                    agent_id: agent_id.clone(),
                    human_key_image: human_ki.clone(),
                    intent_json: intent.clone(),
                    assurance_level: Some(db_assurance),
                    error: Some(e),
                });
            }
        }
    }

    if payload.consume_jti {
        let jti = match claims.get("jti").and_then(|v| v.as_str()) {
            Some(j) if !j.is_empty() => j.to_string(),
            _ => {
                return Json(VerifyAjwtResponse {
                    valid: false,
                    agent_id,
                    human_key_image: human_ki,
                    intent_json: intent,
                    assurance_level,
                    error: Some("A-JWT missing jti; cannot consume".into()),
                });
            }
        };
        let exp = match claims.get("exp").and_then(|v| v.as_i64()) {
            Some(e) => e,
            None => {
                return Json(VerifyAjwtResponse {
                    valid: false,
                    agent_id,
                    human_key_image: human_ki,
                    intent_json: intent,
                    assurance_level,
                    error: Some("A-JWT missing exp".into()),
                });
            }
        };
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        if let Err(e) = ajwt_support::consume_ajwt_jti(&db, &jti, exp) {
            return Json(VerifyAjwtResponse {
                valid: false,
                agent_id,
                human_key_image: human_ki,
                intent_json: intent,
                assurance_level,
                error: Some(e),
            });
        }
    }

    Json(VerifyAjwtResponse {
        valid: true,
        agent_id,
        human_key_image: human_ki,
        intent_json: intent,
        assurance_level,
        error: None,
    })
}

/// GET /agent/list/{human_key_image} — list agents for authenticated human only.
pub async fn list_agents(
    State(state): State<Arc<RwLock<ServerState>>>,
    headers: HeaderMap,
    Path(human_ki): Path<String>,
) -> Result<Json<Vec<AgentRecord>>, (StatusCode, String)> {
    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let session_human = session_key_image(&headers, &jwt_secret).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;
    if session_human != human_ki {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Cannot list agents for another user".into(),
        ));
    }

    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT agent_id, human_key_image, agent_checksum, intent_json, assurance_level, IFNULL(ring_key_image_hex, ''), issued_at, expires_at, revoked
         FROM agents WHERE human_key_image = ?1 ORDER BY issued_at DESC"
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db prepare: {e}")))?;
    let records: Vec<AgentRecord> = stmt
        .query_map(params![human_ki], |row| {
            Ok(AgentRecord {
                agent_id: row.get(0)?,
                human_key_image: row.get(1)?,
                agent_checksum: row.get(2)?,
                intent_json: row.get(3)?,
                assurance_level: row.get(4)?,
                ring_key_image_hex: row.get(5)?,
                issued_at: row.get(6)?,
                expires_at: row.get(7)?,
                revoked: row.get::<_, i64>(8)? != 0,
            })
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db query: {e}")))?
        .flatten()
        .collect();
    Ok(Json(records))
}

/// POST /agent/pop/challenge — one-time PoP challenge for agents with `pop_public_key_b64u` set.
#[derive(Deserialize)]
pub struct AgentPopChallengeRequest {
    pub agent_id: String,
}

#[derive(Serialize)]
pub struct AgentPopChallengeResponse {
    pub pop_challenge_id: String,
    pub challenge: String,
    pub expires_at: i64,
}

pub async fn agent_pop_challenge(
    State(state): State<Arc<RwLock<ServerState>>>,
    headers: HeaderMap,
    Json(payload): Json<AgentPopChallengeRequest>,
) -> Result<Json<AgentPopChallengeResponse>, (StatusCode, String)> {
    if payload.agent_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_id required".into()));
    }
    let jwt_secret = state.read().unwrap().jwt_secret.clone();
    let human = session_key_image(&headers, &jwt_secret).ok_or((
        StatusCode::UNAUTHORIZED,
        "Valid x-sauron-session header required".into(),
    ))?;

    let st = state.read().unwrap();
    let db = st.db.lock().unwrap();
    let (db_human, revoked, exp_a): (String, i64, i64) = db
        .query_row(
            "SELECT human_key_image, revoked, expires_at FROM agents WHERE agent_id = ?1",
            params![&payload.agent_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "agent not found".into()))?;
    if db_human != human {
        return Err((
            StatusCode::FORBIDDEN,
            "agent not owned by this session".into(),
        ));
    }
    if revoked != 0 {
        return Err((StatusCode::UNAUTHORIZED, "agent revoked".into()));
    }
    let now = ajwt_support::now_secs();
    if exp_a < now {
        return Err((StatusCode::UNAUTHORIZED, "agent expired".into()));
    }

    let challenge = ajwt_support::random_hex_32();
    let id = ajwt_support::random_challenge_id();
    // TODO M2-callsite-sweep: handler holds MutexGuard<Connection> for the
    // surrounding agent lookup; switching to Repo::insert_pop_challenge would
    // require dropping the guard early. Legacy path wraps DELETE+INSERT in
    // BEGIN IMMEDIATE so concurrent inserts under SQLite are atomic.
    let exp = ajwt_support::insert_pop_challenge(&db, &id, &payload.agent_id, &challenge, 300)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(AgentPopChallengeResponse {
        pop_challenge_id: id,
        challenge,
        expires_at: exp,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
//  Per-call signature middleware (DPoP-style request binding)
//
//  Closes the "captured A-JWT replayed against a different endpoint or with
//  mutated body" gap that PoP-on-challenge does not cover. Every protected call
//  carries an Ed25519 signature over:
//
//      method | path | sha256(body) | timestamp_ms | nonce
//
//  signed by the agent's registered `pop_public_key_b64u`. Nonce is single-use
//  (consumed atomically in `agent_call_nonces`); timestamp must be within
//  ±SAURON_CALL_SIG_SKEW_MS (default 60s) of server time.
//
//  Headers expected:
//    x-sauron-agent-id   : agent_id whose pop key is used
//    x-sauron-call-ts    : unix milliseconds, ascii-decimal
//    x-sauron-call-nonce : opaque nonce (≤128 chars), single-use
//    x-sauron-call-sig   : base64url(no-pad) Ed25519 signature
// ─────────────────────────────────────────────────────────────────────────────

/// Verified per-call signature context. Attached to request extensions on success.
#[derive(Clone, Debug)]
pub struct VerifiedCallSig {
    pub agent_id: String,
}

const CALL_SIG_BODY_LIMIT: usize = 4 * 1024 * 1024;

/// Try to verify the call signature given the parts and buffered body.
/// Returns the verified context on success, or a (status, message) error on failure.
async fn try_verify_call_sig(
    state: &Arc<RwLock<ServerState>>,
    parts: &axum::http::request::Parts,
    body_bytes: &[u8],
) -> Result<VerifiedCallSig, (StatusCode, String)> {
    let agent_id = parts
        .headers
        .get("x-sauron-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "x-sauron-agent-id header required".into(),
        ))?;
    let call_ts_str = parts
        .headers
        .get("x-sauron-call-ts")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "x-sauron-call-ts header required".into(),
        ))?;
    let call_ts: i64 = call_ts_str.parse().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "x-sauron-call-ts must be unix milliseconds".into(),
        )
    })?;
    let nonce = parts
        .headers
        .get("x-sauron-call-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "x-sauron-call-nonce header required".into(),
        ))?;
    let sig_b64 = parts
        .headers
        .get("x-sauron-call-sig")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "x-sauron-call-sig header required".into(),
        ))?;

    let skew_ms: i64 = std::env::var("SAURON_CALL_SIG_SKEW_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60_000)
        .clamp(1_000, 600_000);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    if (now_ms - call_ts).abs() > skew_ms {
        return Err((
            StatusCode::UNAUTHORIZED,
            "x-sauron-call-ts outside acceptable skew window".into(),
        ));
    }

    let body_hash_hex = hex::encode(Sha256::digest(body_bytes));

    // Pull both the PoP key and the registered checksum in one shot.
    let (pop_pk_b64u, registered_checksum): (String, String) = {
        let st = state.read().unwrap();
        let db = st.db.lock().unwrap();
        db.query_row(
            "SELECT IFNULL(pop_public_key_b64u, ''), agent_checksum
             FROM agents WHERE agent_id = ?1 AND revoked = 0",
            params![agent_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .map_err(|_| (StatusCode::UNAUTHORIZED, "unknown or revoked agent".into()))?
    };
    if pop_pk_b64u.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "agent has no pop_public_key_b64u registered (per-call signature requires PoP-bound agent)".into(),
        ));
    }

    // Gap 4c — config-digest enforcement.
    //
    // Every protected request MUST include `x-sauron-agent-config-digest` matching the
    // server-stored `agents.agent_checksum`. If the agent's runtime flipped its system
    // prompt / tool list / model without first calling /agent/<id>/checksum/update,
    // the digest its runtime computes diverges from what SauronID has on file and
    // every call rejects with 401. The leash cannot be silently bypassed by mutating
    // agent config; either you update SauronID first, or you stop being able to act.
    //
    // Honesty assumption: the runtime computes its own digest from its actual config.
    // A compromised host can lie — that's gap 3, mitigated by hardware attestation.
    let claimed_digest = parts
        .headers
        .get("x-sauron-agent-config-digest")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "x-sauron-agent-config-digest header required (Gap 4 enforcement)".into(),
        ))?;
    use subtle::ConstantTimeEq;
    if claimed_digest.as_bytes().ct_eq(registered_checksum.as_bytes()).unwrap_u8() == 0 {
        return Err((
            StatusCode::UNAUTHORIZED,
            "agent runtime config digest does not match registered checksum (config drift; call /agent/<id>/checksum/update to rotate)".into(),
        ));
    }

    let signing_payload = format!(
        "{}|{}|{}|{}|{}",
        parts.method.as_str(),
        parts.uri.path(),
        body_hash_hex,
        call_ts,
        nonce
    );

    let pk_bytes = URL_SAFE_NO_PAD
        .decode(pop_pk_b64u.trim())
        .map_err(|_| (StatusCode::UNAUTHORIZED, "agent pop key invalid base64url".into()))?;
    let pk_arr: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| (StatusCode::UNAUTHORIZED, "agent pop key wrong length".into()))?;
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "agent pop key not a valid Ed25519 point".into()))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "x-sauron-call-sig invalid base64url".into()))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "x-sauron-call-sig wrong size".into()))?;
    vk.verify(signing_payload.as_bytes(), &sig).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "call signature verification failed".into(),
        )
    })?;

    // Atomic single-use nonce consume — replay protection.
    // Routed through the dual-backend `repo` abstraction (Phase 3 template):
    // SQLite default keeps the existing rusqlite path; Postgres path activates
    // when `SAURON_DB_BACKEND=postgres` + `DATABASE_URL` are set.
    let nonce_exp = call_ts / 1000 + skew_ms / 1000 + 60;
    let repo = state.read().unwrap().repo.clone();
    repo.consume_call_nonce(&agent_id, &nonce, nonce_exp)
        .await
        .map_err(|e| match e {
            crate::repository::RepoError::Replay(s) => (StatusCode::CONFLICT, s),
            crate::repository::RepoError::Backend(s) => {
                (StatusCode::INTERNAL_SERVER_ERROR, s)
            }
        })?;

    Ok(VerifiedCallSig { agent_id })
}

pub async fn require_call_signature(
    State(state): State<Arc<RwLock<ServerState>>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let enforce = match std::env::var("SAURON_REQUIRE_CALL_SIG").ok() {
        Some(v) => {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        }
        None => !crate::runtime_mode::is_development_runtime(),
    };

    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, CALL_SIG_BODY_LIMIT)
        .await
        .map_err(|_| (StatusCode::PAYLOAD_TOO_LARGE, "request body too large".into()))?;

    match try_verify_call_sig(&state, &parts, &body_bytes).await {
        Ok(verified) => {
            let mut req = axum::extract::Request::from_parts(parts, axum::body::Body::from(body_bytes));
            req.extensions_mut().insert(verified);
            Ok(next.run(req).await)
        }
        Err((status, msg)) => {
            if enforce {
                Err((status, msg))
            } else {
                tracing::warn!(
                    target: "sauron::call_sig",
                    enforce = false,
                    status = status.as_u16(),
                    %msg,
                    "call signature verification skipped (advisory mode)"
                );
                let req = axum::extract::Request::from_parts(parts, axum::body::Body::from(body_bytes));
                Ok(next.run(req).await)
            }
        }
    }
}

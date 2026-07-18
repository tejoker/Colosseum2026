//! Ceremony-free production proof verification.
//!
//! SauronID accepts native RISC Zero STARK receipts only.  In particular, the
//! verifier rejects RISC Zero's optional Groth16-compressed receipt, fake
//! development receipts, and unknown future receipt variants before invoking
//! the cryptographic verifier.  The expected guest image ID is selected from
//! operator configuration by `program_id`; it is never supplied by the prover.
//!
//! This removes the Groth16 toxic-waste ceremony from the trust model.  It does
//! not create unconditional truth: security still relies on the reviewed guest
//! program, collision resistance, FRI/Fiat-Shamir assumptions, and a correct
//! verifier implementation.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use once_cell::sync::Lazy;
use risc0_zkvm::{sha::Digest, InnerReceipt, Receipt};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

pub use sauron_transparent_types::{
    TransparentJournal, TransparentStatement, ACTION_POLICY_PROGRAM_ID, JOURNAL_PROTOCOL,
    STATS_PROGRAM_ID,
};

const MAX_RECEIPT_B64_BYTES: usize = 96 * 1024 * 1024;
const MAX_RECEIPT_JSON_BYTES: usize = 72 * 1024 * 1024;
const MAX_JOURNAL_BYTES: usize = 64 * 1024;

static VERIFY_SLOTS: Lazy<Arc<Semaphore>> = Lazy::new(|| {
    let permits = std::env::var("SAURON_TRANSPARENT_VERIFY_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2)
        .clamp(1, 16);
    Arc::new(Semaphore::new(permits))
});

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransparentProofPayload {
    /// Stable identifier for a reviewed guest program.  The server resolves
    /// this to a pinned image ID; callers cannot choose an arbitrary program.
    pub program_id: String,
    /// Base64 (standard alphabet) of the serde-JSON encoded RISC Zero receipt.
    /// JSON is intentionally used at this untrusted boundary because its
    /// deserializer enforces a recursion limit; unrestricted bincode does not.
    pub receipt_b64: String,
}

#[derive(Debug)]
pub enum TransparentProofError {
    Malformed(String),
    Configuration(String),
    Unsupported(String),
    Busy(String),
    Invalid(String),
}

impl std::fmt::Display for TransparentProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(s) => write!(f, "malformed transparent proof: {s}"),
            Self::Configuration(s) => write!(f, "transparent proof configuration: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported proof type: {s}"),
            Self::Busy(s) => write!(f, "transparent verifier busy: {s}"),
            Self::Invalid(s) => write!(f, "transparent proof rejected: {s}"),
        }
    }
}

impl std::error::Error for TransparentProofError {}

fn validate_program_id(program_id: &str) -> Result<(), TransparentProofError> {
    if !matches!(program_id, STATS_PROGRAM_ID | ACTION_POLICY_PROGRAM_ID) {
        return Err(TransparentProofError::Unsupported(format!(
            "program_id '{program_id}' is not a reviewed SauronID guest"
        )));
    }
    Ok(())
}

/// Resolve the reviewed guest image ID from an operator-controlled mapping:
/// `{"sauron-stats-v1":"<64 hex>", ...}`.
fn configured_image_id(program_id: &str) -> Result<Digest, TransparentProofError> {
    validate_program_id(program_id)?;
    let raw = std::env::var("SAURON_TRANSPARENT_IMAGE_IDS_JSON").map_err(|_| {
        TransparentProofError::Configuration(
            "SAURON_TRANSPARENT_IMAGE_IDS_JSON is required; publish and pin the reviewed guest image ID"
                .into(),
        )
    })?;
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&raw)
        .map_err(|e| TransparentProofError::Configuration(format!("image-id map JSON: {e}")))?;
    let image_hex = map
        .get(program_id)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            TransparentProofError::Configuration(format!(
                "no pinned image ID for program_id '{program_id}'"
            ))
        })?
        .trim()
        .trim_start_matches("0x");
    let image_bytes = hex::decode(image_hex).map_err(|_| {
        TransparentProofError::Configuration(format!(
            "image ID for '{program_id}' must be 32-byte hex"
        ))
    })?;
    Digest::try_from(image_bytes.as_slice()).map_err(|_| {
        TransparentProofError::Configuration(format!(
            "image ID for '{program_id}' must be exactly 32 bytes"
        ))
    })
}

/// Startup gate: a production process must pin every public proof program it
/// advertises.  This catches missing or malformed image IDs before the socket
/// starts accepting traffic.
pub fn validate_production_configuration() -> Result<(), String> {
    for program_id in [STATS_PROGRAM_ID, ACTION_POLICY_PROGRAM_ID] {
        configured_image_id(program_id).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn decode_receipt(payload: &TransparentProofPayload) -> Result<Receipt, TransparentProofError> {
    validate_program_id(payload.program_id.trim())?;
    if payload.receipt_b64.is_empty() || payload.receipt_b64.len() > MAX_RECEIPT_B64_BYTES {
        return Err(TransparentProofError::Malformed(format!(
            "receipt_b64 length must be 1..={MAX_RECEIPT_B64_BYTES} bytes"
        )));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload.receipt_b64)
        .map_err(|e| TransparentProofError::Malformed(format!("receipt base64: {e}")))?;
    if bytes.len() > MAX_RECEIPT_JSON_BYTES {
        return Err(TransparentProofError::Malformed(format!(
            "decoded receipt exceeds {MAX_RECEIPT_JSON_BYTES} bytes"
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| TransparentProofError::Malformed(format!("receipt JSON: {e}")))
}

fn require_native_stark(receipt: &Receipt) -> Result<(), TransparentProofError> {
    match &receipt.inner {
        InnerReceipt::Composite(_) | InnerReceipt::Succinct(_) => Ok(()),
        InnerReceipt::Groth16(_) => Err(TransparentProofError::Unsupported(
            "Groth16-compressed RISC Zero receipts are refused; submit a native Composite or Succinct STARK receipt"
                .into(),
        )),
        InnerReceipt::Fake(_) => Err(TransparentProofError::Unsupported(
            "fake development receipt has no cryptographic integrity".into(),
        )),
        _ => Err(TransparentProofError::Unsupported(
            "unknown future receipt variant is fail-closed until reviewed".into(),
        )),
    }
}

fn decode_journal(
    receipt: &Receipt,
    expected_program_id: &str,
) -> Result<TransparentJournal, TransparentProofError> {
    if receipt.journal.bytes.len() > MAX_JOURNAL_BYTES {
        return Err(TransparentProofError::Malformed(format!(
            "journal exceeds {MAX_JOURNAL_BYTES} bytes"
        )));
    }
    let journal: TransparentJournal = receipt
        .journal
        .decode()
        .map_err(|e| TransparentProofError::Malformed(format!("journal decode: {e}")))?;
    if journal.protocol != JOURNAL_PROTOCOL {
        return Err(TransparentProofError::Invalid(format!(
            "journal protocol '{}' is not '{}'",
            journal.protocol, JOURNAL_PROTOCOL
        )));
    }
    if journal.program_id != expected_program_id {
        return Err(TransparentProofError::Invalid(format!(
            "journal program_id '{}' does not match requested '{}'",
            journal.program_id, expected_program_id
        )));
    }
    match (&journal.statement, expected_program_id) {
        (TransparentStatement::Stats { .. }, STATS_PROGRAM_ID)
        | (TransparentStatement::ActionPolicy { .. }, ACTION_POLICY_PROGRAM_ID) => {}
        _ => {
            return Err(TransparentProofError::Invalid(
                "journal statement type does not match the pinned guest program".into(),
            ))
        }
    }
    Ok(journal)
}

/// Verify one untrusted receipt and return only its cryptographically bound
/// public journal.  Verification runs on a bounded blocking pool.  A timed-out
/// verification keeps its semaphore permit until the underlying verifier
/// actually exits, preventing timeout-based task accumulation.
pub async fn verify_transparent_proof(
    payload: &TransparentProofPayload,
) -> Result<TransparentJournal, TransparentProofError> {
    let receipt = decode_receipt(payload)?;
    require_native_stark(&receipt)?;
    let image_id = configured_image_id(payload.program_id.trim())?;
    let journal = decode_journal(&receipt, payload.program_id.trim())?;

    let queue_timeout = Duration::from_secs(2);
    let permit = tokio::time::timeout(queue_timeout, Arc::clone(&VERIFY_SLOTS).acquire_owned())
        .await
        .map_err(|_| TransparentProofError::Busy("verification queue timeout".into()))?
        .map_err(|_| TransparentProofError::Busy("verification queue closed".into()))?;

    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        receipt
            .verify(image_id)
            .map_err(|e| TransparentProofError::Invalid(e.to_string()))
    });
    let verify_timeout = std::env::var("SAURON_TRANSPARENT_VERIFY_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30)
        .clamp(5, 300);
    tokio::time::timeout(Duration::from_secs(verify_timeout), task)
        .await
        .map_err(|_| {
            TransparentProofError::Busy(format!(
                "verification exceeded {verify_timeout}s; worker remains capacity-bounded"
            ))
        })?
        .map_err(|e| TransparentProofError::Invalid(format!("verifier task failed: {e}")))??;

    Ok(journal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_rejects_unknown_fields() {
        let value = serde_json::json!({
            "protocol": JOURNAL_PROTOCOL,
            "program_id": STATS_PROGRAM_ID,
            "statement": {"stats": {
                "tenant_id": "t",
                "checkpoint_id": "c",
                "action_anchor_id": "a",
                "merkle_root": "00",
                "tree_size": 1,
                "agent_id_or_none": null,
                "metric_id": "success_rate",
                "claimed_value": 1000,
                "period_start": 1,
                "period_end": 2,
                "unbound": true
            }}
        });
        assert!(serde_json::from_value::<TransparentJournal>(value).is_err());
    }

    #[test]
    fn only_reviewed_program_ids_are_accepted() {
        assert!(validate_program_id(STATS_PROGRAM_ID).is_ok());
        assert!(validate_program_id(ACTION_POLICY_PROGRAM_ID).is_ok());
        assert!(validate_program_id("attacker-program").is_err());
    }
}

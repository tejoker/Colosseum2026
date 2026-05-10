//! Vendor-neutral hardware attestation.
//!
//! The general primitive is: a piece of hardware (TPM 2.0, Intel SGX, AMD
//! SEV-SNP, ARM CCA, AWS Nitro, Apple Secure Enclave) signs a document
//! containing a measurement of the runtime state. SauronID verifies:
//!
//!   1. The document signature with the hardware's exposed public key.
//!   2. The certificate chain rooting in a known manufacturer cert (or an
//!      operator-controlled root for self-signed deployments).
//!   3. The measurement matches what the operator registered as expected.
//!
//! This module supports multiple `AttestationKind`s. Operators pick the kind
//! that matches their hardware:
//!
//! | Kind            | Format             | Manufacturer root | Cloud-agnostic |
//! |-----------------|--------------------|-------------------|---------------|
//! | `tpm2_quote`    | TPMS_ATTEST + sig  | TPM-vendor cert   | yes (any HW)  |
//! | `sgx_quote`     | SGX QE3 / DCAP     | Intel root        | yes           |
//! | `sev_snp`       | SEV-SNP report     | AMD root          | yes           |
//! | `arm_cca`       | ARM CCA token      | ARM root          | yes           |
//! | `nitro_enclave` | AWS Nitro COSE     | AWS root          | AWS-only      |
//! | `apple_secure`  | DeviceCheck assert | Apple root        | macOS/iOS only|
//! | `ed25519_self`  | Ed25519(payload)   | OPERATOR root     | yes           |
//!
//! For this commit we ship the primitive (`verify_attestation`) and the
//! `Ed25519Self` path (operator-controlled root). The other kinds are
//! recognised, declared in the enum, and produce a clean
//! `AttestationError::NotImplemented(kind)` until the per-kind crypto path
//! lands. **None of them require AWS** — all are open-standard.
//!
//! Roadmap to full coverage:
//!
//!   - `Tpm2Quote`: parse `TPMS_ATTEST` structure with `nom`, verify EK→AIK
//!     cert chain via `webpki`, signature via `ring`. Vendor roots ship as
//!     static bytes (Infineon, STMicro, Microsoft, Intel, AMD, IBM).
//!   - `SgxQuote`: parse DCAP quote with `dcap-rs`-style logic, verify
//!     against Intel SGX root cert.
//!   - `SevSnpReport`: parse SEV-SNP attestation report, verify against AMD
//!     EPYC milan/genoa/turin root.
//!   - `NitroEnclave`: COSE_Sign1 verification against AWS Nitro root cert.
//!     Code-equivalent to `aws-nitro-enclaves-cose` but standalone — no AWS
//!     SDK dependency required.
//!
//! The operator can opt into hardware-rooted attestation incrementally: ship
//! Ed25519Self today, swap to TPM2 next quarter, add SGX after that. SauronID
//! treats them all the same once the verification function returns OK.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    None,
    Ed25519Self,
    Tpm2Quote,
    SgxQuote,
    SevSnp,
    ArmCca,
    NitroEnclave,
    AppleSecure,
}

impl AttestationKind {
    pub fn parse(s: &str) -> Self {
        match s {
            "ed25519_self" => Self::Ed25519Self,
            "tpm2_quote" | "tpm2" => Self::Tpm2Quote,
            "sgx_quote" | "sgx" => Self::SgxQuote,
            "sev_snp" | "sev" => Self::SevSnp,
            "arm_cca" | "cca" => Self::ArmCca,
            "nitro_enclave" | "nitro" => Self::NitroEnclave,
            "apple_secure" | "apple" => Self::AppleSecure,
            _ => Self::None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "",
            Self::Ed25519Self => "ed25519_self",
            Self::Tpm2Quote => "tpm2_quote",
            Self::SgxQuote => "sgx_quote",
            Self::SevSnp => "sev_snp",
            Self::ArmCca => "arm_cca",
            Self::NitroEnclave => "nitro_enclave",
            Self::AppleSecure => "apple_secure",
        }
    }
}

#[derive(Debug)]
pub enum AttestationError {
    Decode(String),
    BadSignature,
    BadCertChain(String),
    MeasurementMismatch { expected: String, got: String },
    NotImplemented(&'static str),
    Empty,
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(s) => write!(f, "attestation decode failure: {s}"),
            Self::BadSignature => write!(f, "attestation signature did not verify"),
            Self::BadCertChain(s) => write!(f, "attestation cert chain rejected: {s}"),
            Self::MeasurementMismatch { expected, got } => write!(
                f,
                "attestation measurement mismatch: expected {expected}, got {got}"
            ),
            Self::NotImplemented(kind) => write!(
                f,
                "attestation kind '{kind}' is recognised but verification is not yet implemented in this build (TPM2/SGX/SEV/CCA/Nitro/Apple roadmapped — see attestation.rs)"
            ),
            Self::Empty => write!(f, "no attestation registered for this agent"),
        }
    }
}

/// What the verifier compares against.
#[derive(Debug, Clone)]
pub struct AttestationContext<'a> {
    /// Hex-encoded SHA-256 of the runtime measurement the operator expects.
    /// For TPM2: the canonical hash of the PCR set. For SGX: MR_ENCLAVE.
    /// For Ed25519Self: hash of the blob payload.
    pub expected_measurement_hex: &'a str,
    /// Public key trusted to sign the attestation. For self-signed (Ed25519Self):
    /// operator-controlled key. For TPM2: the AIK pubkey extracted from the
    /// EK certificate chain. For Nitro: the leaf cert from the COSE document.
    pub trusted_pubkey_b64u: &'a str,
}

/// Verify an attestation blob. Returns `Ok` only if the document is genuine,
/// the cert chain validates, and the measurement matches what the operator
/// registered.
pub fn verify_attestation(
    kind: AttestationKind,
    blob: &[u8],
    ctx: &AttestationContext,
) -> Result<(), AttestationError> {
    match kind {
        AttestationKind::None => Err(AttestationError::Empty),
        AttestationKind::Ed25519Self => verify_ed25519_self(blob, ctx),
        AttestationKind::Tpm2Quote => Err(AttestationError::NotImplemented("tpm2_quote")),
        AttestationKind::SgxQuote => Err(AttestationError::NotImplemented("sgx_quote")),
        AttestationKind::SevSnp => Err(AttestationError::NotImplemented("sev_snp")),
        AttestationKind::ArmCca => Err(AttestationError::NotImplemented("arm_cca")),
        AttestationKind::NitroEnclave => Err(AttestationError::NotImplemented("nitro_enclave")),
        AttestationKind::AppleSecure => Err(AttestationError::NotImplemented("apple_secure")),
    }
}

/// Ed25519-self attestation format:
///
///   blob = base64url(payload_json) || "." || base64url(signature)
///
/// where:
///
///   payload_json = `{"measurement": "<hex>", "ts": <unix>, "agent_id": "<id>"}`
///   signature    = Ed25519(payload_json_bytes, operator_root_privkey)
///
/// This lets an operator sign their own runtime measurements with a key they
/// hold offline (HSM, YubiKey, air-gapped laptop). Not as strong as a TPM-
/// rooted attestation — the operator still has to honestly compute the
/// measurement — but cryptographically prevents tampering once signed.
fn verify_ed25519_self(
    blob: &[u8],
    ctx: &AttestationContext,
) -> Result<(), AttestationError> {
    let blob_str = std::str::from_utf8(blob)
        .map_err(|e| AttestationError::Decode(format!("blob is not utf-8: {e}")))?;
    let parts: Vec<&str> = blob_str.split('.').collect();
    if parts.len() != 2 {
        return Err(AttestationError::Decode(
            "expected '<payload_b64u>.<sig_b64u>'".into(),
        ));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| AttestationError::Decode(format!("payload b64u: {e}")))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| AttestationError::Decode(format!("signature b64u: {e}")))?;

    let pk_bytes = URL_SAFE_NO_PAD
        .decode(ctx.trusted_pubkey_b64u.trim())
        .map_err(|e| AttestationError::BadCertChain(format!("pubkey b64u: {e}")))?;
    let pk_arr: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AttestationError::BadCertChain("pubkey is not 32 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| AttestationError::BadCertChain("pubkey is not a valid Ed25519 point".into()))?;

    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| AttestationError::BadSignature)?;
    vk.verify(&payload_bytes, &sig)
        .map_err(|_| AttestationError::BadSignature)?;

    // Decode payload to extract measurement.
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AttestationError::Decode(format!("payload not JSON: {e}")))?;
    let claimed_measurement = payload
        .get("measurement")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AttestationError::Decode("payload missing 'measurement'".into()))?;

    if claimed_measurement != ctx.expected_measurement_hex {
        return Err(AttestationError::MeasurementMismatch {
            expected: ctx.expected_measurement_hex.to_string(),
            got: claimed_measurement.to_string(),
        });
    }
    Ok(())
}

/// Helper for deployments that want to use the Ed25519Self format: deterministic
/// hash function used as the measurement input. Operators run this against
/// their actual runtime config (e.g. binary SHA + system prompt SHA + tool
/// list SHA) and put the resulting hex into `payload_json.measurement` before
/// signing.
pub fn measurement_hash(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
        h.update(b"|");
    }
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn ed25519_self_blob(privkey: &ed25519_dalek::SigningKey, measurement_hex: &str) -> Vec<u8> {
        let payload = serde_json::json!({
            "measurement": measurement_hex,
            "ts": 1_000_000_000,
            "agent_id": "agt_test",
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let sig = privkey.sign(&payload_bytes);
        let blob = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload_bytes),
            URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        );
        blob.into_bytes()
    }

    #[test]
    fn ed25519_self_round_trip_passes() {
        let mut csprng = rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk_b64u = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let measurement = "deadbeefcafebabe";
        let blob = ed25519_self_blob(&sk, measurement);
        let ctx = AttestationContext {
            expected_measurement_hex: measurement,
            trusted_pubkey_b64u: &pk_b64u,
        };
        verify_attestation(AttestationKind::Ed25519Self, &blob, &ctx).unwrap();
    }

    #[test]
    fn ed25519_self_wrong_pubkey_rejected() {
        let mut csprng = rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let other_sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let other_pk = URL_SAFE_NO_PAD.encode(other_sk.verifying_key().to_bytes());
        let blob = ed25519_self_blob(&sk, "abcd");
        let ctx = AttestationContext {
            expected_measurement_hex: "abcd",
            trusted_pubkey_b64u: &other_pk,
        };
        match verify_attestation(AttestationKind::Ed25519Self, &blob, &ctx) {
            Err(AttestationError::BadSignature) => {}
            other => panic!("expected BadSignature, got {:?}", other),
        }
    }

    #[test]
    fn ed25519_self_wrong_measurement_rejected() {
        let mut csprng = rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let blob = ed25519_self_blob(&sk, "claimed_measurement");
        let ctx = AttestationContext {
            expected_measurement_hex: "expected_different",
            trusted_pubkey_b64u: &pk,
        };
        match verify_attestation(AttestationKind::Ed25519Self, &blob, &ctx) {
            Err(AttestationError::MeasurementMismatch { .. }) => {}
            other => panic!("expected MeasurementMismatch, got {:?}", other),
        }
    }

    #[test]
    fn ed25519_self_tampered_payload_rejected() {
        let mut csprng = rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let blob = ed25519_self_blob(&sk, "real");
        // Replace the payload section with a different b64u (signature stays).
        let blob_str = std::str::from_utf8(&blob).unwrap();
        let mut parts = blob_str.split('.');
        let _orig_payload = parts.next().unwrap();
        let sig = parts.next().unwrap();
        let mutated_payload = serde_json::json!({"measurement":"fake","ts":0,"agent_id":"x"});
        let mutated_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&mutated_payload).unwrap());
        let mutated_blob = format!("{}.{}", mutated_b64, sig).into_bytes();
        let ctx = AttestationContext {
            expected_measurement_hex: "fake",
            trusted_pubkey_b64u: &pk,
        };
        match verify_attestation(AttestationKind::Ed25519Self, &mutated_blob, &ctx) {
            Err(AttestationError::BadSignature) => {}
            other => panic!("expected BadSignature, got {:?}", other),
        }
    }

    #[test]
    fn unimplemented_kinds_return_clean_error() {
        let ctx = AttestationContext {
            expected_measurement_hex: "x",
            trusted_pubkey_b64u: "x",
        };
        for k in [
            AttestationKind::Tpm2Quote,
            AttestationKind::SgxQuote,
            AttestationKind::SevSnp,
            AttestationKind::ArmCca,
            AttestationKind::NitroEnclave,
            AttestationKind::AppleSecure,
        ] {
            match verify_attestation(k, b"any", &ctx) {
                Err(AttestationError::NotImplemented(_)) => {}
                other => panic!("kind {:?} expected NotImplemented, got {:?}", k, other),
            }
        }
    }

    #[test]
    fn measurement_hash_is_deterministic() {
        let h1 = measurement_hash(&[b"binary_sha:abc", b"prompt_sha:def"]);
        let h2 = measurement_hash(&[b"binary_sha:abc", b"prompt_sha:def"]);
        assert_eq!(h1, h2);
    }
}

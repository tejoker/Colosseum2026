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
//! Sprint 6 module layout (this file is `attestation/mod.rs`):
//!
//!   - [`abstraction`] — vendor-neutral [`AttestationVerifier`] trait + the
//!     [`AttestationKind`] / [`AttestationError`] / [`AttestationContext`]
//!     enums and structs every backend shares.
//!   - [`ed25519_self`] — operator-rooted Ed25519 self-attestation (M1).
//!   - [`tpm2`] — TPM 2.0 quote parser + AIK sig verification + cert chain
//!     walker (M2 of the TPM2 PoP roadmap).
//!   - [`nitro`] — AWS Nitro JSON + CBOR dispatcher.
//!   - [`nitro_pcr`] — PCR comparison helpers shared by both Nitro paths.
//!   - [`cbor`] — hand-rolled CBOR / COSE_Sign1 parser used by [`nitro`].
//!   - [`handlers`] — `/v1/attestation/nitro/verify` HTTP handler.
//!
//! The top-level `verify_attestation()` dispatcher + the public types
//! re-exported from this `mod.rs` are the stable API surface. Internal
//! reshuffles inside the sub-modules MUST NOT break callers — every symbol
//! exported by the legacy `attestation.rs` file is re-exported here under
//! the same path (`crate::attestation::Foo`). The integration test path
//! `crate::attestation_cbor` is also preserved through a re-export in
//! `lib.rs`.

pub mod abstraction;
pub mod cbor;
pub mod ed25519_self;
pub mod handlers;
pub mod nitro;
pub mod nitro_pcr;
pub mod tpm2;

// ─── Public re-exports — these mirror the pre-refactor `attestation.rs`
//     surface. Nothing outside this module should import from a sub-module
//     directly; everything goes through `crate::attestation::Foo`.

pub use abstraction::AttestationVerifier;
pub use ed25519_self::{measurement_hash, verify_ed25519_self, Ed25519SelfVerifier};
pub use nitro::{
    load_nitro_root_pem_path, parse_nitro_cose_blob, parse_nitro_dev, verify_nitro_enclave,
    NitroAttestationDoc, NitroAttestationEnvelope, NitroEnclaveVerifier,
};
pub use nitro_pcr::verify_nitro_pcrs;
pub use tpm2::{
    detect_tpmt_signature_alg, load_trusted_tpm2_roots, parse_tpms_attest, verify_aik_cert_chain,
    verify_aik_signature, verify_pcr_digest, TpmPublicKey, Tpm2QuotePayload, Tpm2QuoteVerifier,
    TpmsAttest, TpmsClockInfo, TpmsPcrSelection, TpmsQuoteInfo, TPM_GENERATED_VALUE,
    TPM_ST_ATTEST_QUOTE,
};

use serde::{Deserialize, Serialize};

// ─── AttestationKind ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    None,
    /// Legacy default: PoP key is derived server-side from `jwt_secret`. Carries
    /// no hardware proof. Refused in production unless explicitly opted in
    /// (see `check_server_derived_allowed`). This makes M1 of the TPM2 PoP
    /// roadmap meaningful: operators have to consciously accept the trust
    /// assumption that `jwt_secret` compromise = full agent impersonation.
    ServerDerived,
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
            "server_derived" | "server" => Self::ServerDerived,
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
            Self::ServerDerived => "server_derived",
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

/// Production-grade gate for the legacy `ServerDerived` path.
///
/// Returns `Ok(())` if the caller is allowed to register / verify an agent
/// whose PoP key is server-derived. Returns `Err(AttestationError::Empty)`
/// with a descriptive message otherwise.
///
/// Policy (M1 of the TPM2 PoP roadmap):
///   - `SAURON_ALLOW_SERVER_DERIVED_POP=1` → always allow (operator opt-in).
///   - `ENV=development` (or `SAURON_ENV=development|dev|local`) → allow with
///     a warning logged elsewhere.
///   - Otherwise (production default) → refuse.
///
/// This makes the previous insecure default explicit. Operators upgrading to
/// `Ed25519Self` (today) or `Tpm2Quote` (M2) can drop the override.
pub fn check_server_derived_allowed() -> Result<(), AttestationError> {
    if let Ok(v) = std::env::var("SAURON_ALLOW_SERVER_DERIVED_POP") {
        let low = v.to_ascii_lowercase();
        if v == "1" || low == "true" || low == "yes" {
            return Ok(());
        }
    }
    let env = std::env::var("ENV")
        .or_else(|_| std::env::var("SAURON_ENV"))
        .unwrap_or_else(|_| "production".to_string())
        .to_ascii_lowercase();
    if matches!(env.as_str(), "development" | "dev" | "local") {
        return Ok(());
    }
    Err(AttestationError::BadCertChain(
        "server-derived PoP is refused in production: set SAURON_ALLOW_SERVER_DERIVED_POP=1 to opt in, or upgrade to ed25519_self / tpm2_quote (see docs/roadmap.md Plan 1)".into(),
    ))
}

// ─── AttestationError ────────────────────────────────────────────────────

#[derive(Debug)]
pub enum AttestationError {
    Decode(String),
    BadSignature,
    BadCertChain(String),
    MeasurementMismatch { expected: String, got: String },
    NotImplemented(&'static str),
    /// Caller submitted a structurally well-formed payload but the verifier is
    /// only partially implemented (M1 ships parsing; M2 ships verification).
    /// Carries a static message pointing at the roadmap entry.
    PartialImplementation(&'static str),
    /// Caller submitted a payload that does not parse: missing fields, invalid
    /// base64, invalid PEM, etc. Distinct from `BadSignature` (which means the
    /// payload parsed but the cryptographic check failed).
    Malformed(String),
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
            Self::PartialImplementation(msg) => write!(
                f,
                "attestation partially implemented: {msg}"
            ),
            Self::Malformed(s) => write!(f, "attestation payload malformed: {s}"),
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

// ─── Top-level dispatcher ────────────────────────────────────────────────

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
        AttestationKind::ServerDerived => check_server_derived_allowed(),
        AttestationKind::Ed25519Self => Ed25519SelfVerifier.verify(blob, ctx),
        AttestationKind::Tpm2Quote => Tpm2QuoteVerifier.verify(blob, ctx),
        AttestationKind::SgxQuote => Err(AttestationError::NotImplemented("sgx_quote")),
        AttestationKind::SevSnp => Err(AttestationError::NotImplemented("sev_snp")),
        AttestationKind::ArmCca => Err(AttestationError::NotImplemented("arm_cca")),
        AttestationKind::NitroEnclave => NitroEnclaveVerifier.verify(blob, ctx),
        AttestationKind::AppleSecure => Err(AttestationError::NotImplemented("apple_secure")),
    }
}

// ─── Tests common to the dispatcher (kept in mod.rs because they cross
//     multiple backends). Per-backend tests live in the sub-modules.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unimplemented_kinds_return_clean_error() {
        // M1 of the TPM2/Nitro roadmap: `Tpm2Quote` + `NitroEnclave` are no
        // longer `NotImplemented` — they return `Malformed` for garbage input
        // and `PartialImplementation` / `MeasurementMismatch` for well-formed
        // input. The other hardware kinds remain `NotImplemented` until their
        // respective milestones land.
        let ctx = AttestationContext {
            expected_measurement_hex: "x",
            trusted_pubkey_b64u: "x",
        };
        for k in [
            AttestationKind::SgxQuote,
            AttestationKind::SevSnp,
            AttestationKind::ArmCca,
            AttestationKind::AppleSecure,
        ] {
            match verify_attestation(k, b"any", &ctx) {
                Err(AttestationError::NotImplemented(_)) => {}
                other => panic!("kind {:?} expected NotImplemented, got {:?}", k, other),
            }
        }
    }

    // `std::env::set_var` is process-wide. To avoid one test stomping another's
    // env (cargo runs tests in parallel by default), we serialise the three
    // ServerDerived tests behind a mutex.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Snapshot prior values, then apply.
        let snapshots: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| (k.to_string(), std::env::var(*k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        f();
        // Restore.
        for (k, prior) in snapshots {
            match prior {
                Some(val) => std::env::set_var(&k, val),
                None => std::env::remove_var(&k),
            }
        }
    }

    #[test]
    fn test_register_with_server_derived_pop_refused_in_production() {
        with_env(
            &[
                ("ENV", Some("production")),
                ("SAURON_ENV", None),
                ("SAURON_ALLOW_SERVER_DERIVED_POP", None),
            ],
            || {
                let ctx = AttestationContext {
                    expected_measurement_hex: "x",
                    trusted_pubkey_b64u: "x",
                };
                match verify_attestation(AttestationKind::ServerDerived, b"", &ctx) {
                    Err(AttestationError::BadCertChain(msg)) => {
                        assert!(
                            msg.contains("SAURON_ALLOW_SERVER_DERIVED_POP"),
                            "error should mention the opt-in env var, got: {msg}"
                        );
                    }
                    other => panic!(
                        "expected BadCertChain refusing ServerDerived in production, got {:?}",
                        other
                    ),
                }
            },
        );
    }

    #[test]
    fn test_register_with_server_derived_pop_allowed_with_explicit_flag() {
        with_env(
            &[
                ("ENV", Some("production")),
                ("SAURON_ENV", None),
                ("SAURON_ALLOW_SERVER_DERIVED_POP", Some("1")),
            ],
            || {
                let ctx = AttestationContext {
                    expected_measurement_hex: "x",
                    trusted_pubkey_b64u: "x",
                };
                verify_attestation(AttestationKind::ServerDerived, b"", &ctx).expect(
                    "ServerDerived should be allowed with SAURON_ALLOW_SERVER_DERIVED_POP=1",
                );
            },
        );
    }

    #[test]
    fn test_register_with_server_derived_pop_allowed_in_development() {
        with_env(
            &[
                ("ENV", Some("development")),
                ("SAURON_ENV", None),
                ("SAURON_ALLOW_SERVER_DERIVED_POP", None),
            ],
            || {
                let ctx = AttestationContext {
                    expected_measurement_hex: "x",
                    trusted_pubkey_b64u: "x",
                };
                verify_attestation(AttestationKind::ServerDerived, b"", &ctx)
                    .expect("ServerDerived should be allowed in development runtime");
            },
        );
    }
}

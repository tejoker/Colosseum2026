//! Vendor-neutral verifier trait.
//!
//! Every per-vendor backend (Ed25519 self-signed, TPM2 quote, AWS Nitro,
//! eventually SGX / SEV-SNP / ARM CCA / Apple Secure Enclave) implements
//! [`AttestationVerifier`]. The top-level [`super::verify_attestation`]
//! dispatcher just routes by [`super::AttestationKind`] and calls
//! `.verify(blob, ctx)`.
//!
//! Implementations are zero-sized marker types so the trait is dispatched
//! statically and the dispatcher stays branch-predictable. New vendors slot
//! in by adding a backend module, implementing the trait on its ZST, and
//! adding the variant + dispatch arm in [`super::AttestationKind`] /
//! [`super::verify_attestation`].

use super::{AttestationContext, AttestationError};

/// Verify a vendor-specific attestation blob.
///
/// Contract:
///   - Returns `Ok(())` only when the blob is genuine (signature OK, cert
///     chain OK if applicable) AND the measurement / PCR set matches
///     `ctx.expected_measurement_hex`.
///   - Returns `Err(AttestationError::Malformed)` for structurally invalid
///     blobs (bad base64, missing fields, wrong magic, etc.).
///   - Returns `Err(AttestationError::BadSignature)` for cryptographically
///     invalid blobs (parsed cleanly but the signature does not match).
///   - Returns `Err(AttestationError::BadCertChain)` for chain-validation
///     failures or operator-policy refusals (e.g. dev mode rejected in prod).
///   - Returns `Err(AttestationError::PartialImplementation)` when the
///     backend is wired up but the operator has not configured a required
///     piece of state (vendor roots, AWS Nitro root cert).
///   - Returns `Err(AttestationError::MeasurementMismatch)` when the
///     signature path passes but the measurement disagrees with the
///     operator-registered expectation.
pub trait AttestationVerifier {
    /// Run the full per-vendor verification flow.
    fn verify(&self, blob: &[u8], ctx: &AttestationContext) -> Result<(), AttestationError>;
}

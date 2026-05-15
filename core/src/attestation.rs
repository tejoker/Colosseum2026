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
//! | `server_derived`| (no proof)         | OPERATOR root     | yes (legacy)  |
//!
//! For this commit we ship the primitive (`verify_attestation`) and the
//! `Ed25519Self` path (operator-controlled root). The other kinds are
//! recognised, declared in the enum, and produce a clean
//! `AttestationError::NotImplemented(kind)` until the per-kind crypto path
//! lands. **None of them require AWS** — all are open-standard.
//!
//! `ServerDerived` is the legacy default for deployments where the PoP key is
//! derived from `jwt_secret`. It carries no hardware proof and is opt-in for
//! production — see `check_server_derived_allowed`. Operators upgrade to
//! `Ed25519Self` (today) or `Tpm2Quote` (M2) to remove the operator-trust
//! assumption.
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
use subtle::ConstantTimeEq;

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
        AttestationKind::Ed25519Self => verify_ed25519_self(blob, ctx),
        AttestationKind::Tpm2Quote => verify_tpm2_quote(blob, ctx),
        AttestationKind::SgxQuote => Err(AttestationError::NotImplemented("sgx_quote")),
        AttestationKind::SevSnp => Err(AttestationError::NotImplemented("sev_snp")),
        AttestationKind::ArmCca => Err(AttestationError::NotImplemented("arm_cca")),
        AttestationKind::NitroEnclave => Err(AttestationError::NotImplemented("nitro_enclave")),
        AttestationKind::AppleSecure => Err(AttestationError::NotImplemented("apple_secure")),
    }
}

/// Structured payload submitted by an operator wishing to attest with a TPM2
/// quote. The five fields together let the M2 verifier:
///   1. Decode the `TPMS_ATTEST` blob and its signature.
///   2. Walk the AIK certificate up to the EK certificate chain.
///   3. Walk the EK chain to a known TPM-vendor root (Infineon, STMicro,
///      Microsoft, Intel, AMD, IBM).
///   4. Check the PCR set in the attest blob matches what the operator
///      registered as the expected measurement.
///
/// M1 ships only field parsing; the cert-chain walker is M2 — see
/// `docs/roadmap.md` Plan 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tpm2QuotePayload {
    /// Base64-encoded TPM2 quote (raw signature output).
    pub quote_b64: String,
    /// Base64-encoded TPMS_ATTEST structure that was signed.
    pub attest_b64: String,
    /// Base64-encoded raw signature bytes.
    pub signature_b64: String,
    /// PEM-encoded Attestation Identity Key (AIK) certificate.
    pub aik_cert_pem: String,
    /// PEM-encoded Endorsement Key (EK) certificate chain (one or more certs
    /// concatenated).
    pub ek_cert_chain_pem: String,
}

impl Tpm2QuotePayload {
    /// Parse a JSON-encoded TPM2 quote payload. Returns `Malformed` when any
    /// required field is missing, or when base64 / PEM markers are absent or
    /// invalid.
    pub fn parse_json(blob: &[u8]) -> Result<Self, AttestationError> {
        let v: serde_json::Value = serde_json::from_slice(blob).map_err(|e| {
            AttestationError::Malformed(format!("tpm2 quote payload not JSON: {e}"))
        })?;
        let get = |k: &str| -> Result<String, AttestationError> {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    AttestationError::Malformed(format!("tpm2 quote payload missing field '{k}'"))
                })
        };
        let payload = Tpm2QuotePayload {
            quote_b64: get("quote_b64")?,
            attest_b64: get("attest_b64")?,
            signature_b64: get("signature_b64")?,
            aik_cert_pem: get("aik_cert_pem")?,
            ek_cert_chain_pem: get("ek_cert_chain_pem")?,
        };
        payload.validate_shape()?;
        Ok(payload)
    }

    /// Cheap structural checks: non-empty + base64-decodable + PEM markers
    /// present. Does NOT verify the signature or cert chain — that is M2 work.
    pub fn validate_shape(&self) -> Result<(), AttestationError> {
        use base64::engine::general_purpose::STANDARD as B64;
        for (name, val) in [
            ("quote_b64", &self.quote_b64),
            ("attest_b64", &self.attest_b64),
            ("signature_b64", &self.signature_b64),
        ] {
            if val.trim().is_empty() {
                return Err(AttestationError::Malformed(format!(
                    "tpm2 quote field '{name}' is empty"
                )));
            }
            B64.decode(val.as_bytes()).map_err(|e| {
                AttestationError::Malformed(format!(
                    "tpm2 quote field '{name}' invalid base64: {e}"
                ))
            })?;
        }
        for (name, val) in [
            ("aik_cert_pem", &self.aik_cert_pem),
            ("ek_cert_chain_pem", &self.ek_cert_chain_pem),
        ] {
            if val.trim().is_empty() {
                return Err(AttestationError::Malformed(format!(
                    "tpm2 quote field '{name}' is empty"
                )));
            }
            if !val.contains("-----BEGIN CERTIFICATE-----")
                || !val.contains("-----END CERTIFICATE-----")
            {
                return Err(AttestationError::Malformed(format!(
                    "tpm2 quote field '{name}' is not a PEM certificate"
                )));
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// M2 of TPM2 PoP roadmap: real TPMS_ATTEST parser + AIK signature verification
// + EK→AIK cert-chain walker (operator-supplied vendor roots) + PCR digest
// comparison. See docs/roadmap.md Plan 1.
// ─────────────────────────────────────────────────────────────────────────────

/// TPM_GENERATED_VALUE — every TPMS_ATTEST starts with this magic to prove the
/// payload originated inside the TPM rather than being externally crafted.
pub const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
/// TPM_ST_ATTEST_QUOTE — the only `type` value M2 accepts.
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

// TPM_ALG_ID values (TCG TPM 2.0 Lib Spec Part 2 §6.3) used in TPMT_SIGNATURE.
const TPM_ALG_RSASSA: u16 = 0x0014;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_EDDSA: u16 = 0x001b;
// Hash algs used to pick the ring verifier.
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_SHA384: u16 = 0x000c;
const TPM_ALG_SHA1: u16 = 0x0004;

/// Decoded view of a TPM 2.0 quote (`TPMS_ATTEST` with `TPMS_QUOTE_INFO`).
/// Mirrors the spec field-for-field for the fields the verifier actually uses;
/// raw `extraData`, `qualifiedSigner` bytes are exposed for callers that want
/// to bind them to additional context (nonce-from-host, agent_id, etc.).
#[derive(Debug, Clone)]
pub struct TpmsAttest {
    pub magic: u32,
    pub kind: u16,
    pub qualified_signer: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub clock_info: TpmsClockInfo,
    pub firmware_version: u64,
    pub quote: TpmsQuoteInfo,
}

#[derive(Debug, Clone, Copy)]
pub struct TpmsClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: u8,
}

#[derive(Debug, Clone)]
pub struct TpmsQuoteInfo {
    pub pcr_select: Vec<TpmsPcrSelection>,
    pub pcr_digest: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TpmsPcrSelection {
    pub hash_alg: u16,
    pub pcr_select_bitmap: Vec<u8>,
}

/// Public key extracted from an AIK certificate (or supplied directly by the
/// caller in tests). Variants match the algorithms M2 verifies.
#[derive(Debug, Clone)]
pub enum TpmPublicKey {
    Ed25519([u8; 32]),
    /// SEC1 uncompressed P-256 point (0x04 || X || Y), 65 bytes.
    EcdsaP256(Vec<u8>),
    /// RSA SubjectPublicKeyInfo DER (the form `ring` expects via
    /// `RsaPublicKey::from_public_key_der`). Operators typically extract this
    /// from the AIK certificate's SPKI.
    RsaPkcs1Spki(Vec<u8>),
}

/// Minimal byte cursor for TPM binary structures. Big-endian throughout per the
/// TCG spec. Errors carry the field name for actionable operator feedback.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn need(&self, n: usize, what: &str) -> Result<(), AttestationError> {
        if self.remaining() < n {
            return Err(AttestationError::Malformed(format!(
                "TPMS_ATTEST truncated reading {what}: need {n} bytes, have {}",
                self.remaining()
            )));
        }
        Ok(())
    }

    fn u8(&mut self, what: &str) -> Result<u8, AttestationError> {
        self.need(1, what)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn u16(&mut self, what: &str) -> Result<u16, AttestationError> {
        self.need(2, what)?;
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn u32(&mut self, what: &str) -> Result<u32, AttestationError> {
        self.need(4, what)?;
        let v = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn u64(&mut self, what: &str) -> Result<u64, AttestationError> {
        self.need(8, what)?;
        let v = u64::from_be_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    fn bytes(&mut self, n: usize, what: &str) -> Result<Vec<u8>, AttestationError> {
        self.need(n, what)?;
        let v = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }

    /// TPM2B_<X>: `u16 length || length bytes`.
    ///
    /// Hardened against a malicious blob that declares an enormous TPM2B length
    /// (up to 65_535) against a tiny remaining buffer. `bytes()` already checks
    /// availability before copying, but `Vec::with_capacity`-style hot paths
    /// elsewhere could still over-allocate; explicitly comparing `len` against
    /// the remaining buffer surfaces a precise `Malformed` error and prevents
    /// any future allocator-touching change from regressing.
    fn tpm2b(&mut self, what: &str) -> Result<Vec<u8>, AttestationError> {
        let len = self.u16(what)? as usize;
        if len > self.remaining() {
            return Err(AttestationError::Malformed(format!(
                "{}: TPM2B length {} exceeds remaining buffer {}",
                what,
                len,
                self.remaining()
            )));
        }
        self.bytes(len, what)
    }
}

/// Parse a TPMS_ATTEST byte stream emitted by `TPM2_Quote`. Returns the
/// decoded structure or a `Malformed` error pointing at the offending field.
/// Hardens against the two most common attacker tricks: wrong magic (forged
/// blob built outside the TPM) and wrong attest type (re-using a non-quote
/// attestation, e.g. NV-read certify).
pub fn parse_tpms_attest(bytes: &[u8]) -> Result<TpmsAttest, AttestationError> {
    let mut c = Cursor::new(bytes);
    let magic = c.u32("magic")?;
    if magic != TPM_GENERATED_VALUE {
        return Err(AttestationError::Malformed(format!(
            "TPMS_ATTEST magic 0x{magic:08x} != TPM_GENERATED_VALUE (0x{:08x}); blob did not originate inside a TPM",
            TPM_GENERATED_VALUE
        )));
    }
    let kind = c.u16("type")?;
    if kind != TPM_ST_ATTEST_QUOTE {
        return Err(AttestationError::Malformed(format!(
            "TPMS_ATTEST type 0x{kind:04x} != TPM_ST_ATTEST_QUOTE (0x{:04x}); only quote attestations are accepted",
            TPM_ST_ATTEST_QUOTE
        )));
    }
    let qualified_signer = c.tpm2b("qualifiedSigner")?;
    let extra_data = c.tpm2b("extraData")?;

    // TPMS_CLOCK_INFO: u64 clock || u32 resetCount || u32 restartCount || u8 safe
    let clock = c.u64("clockInfo.clock")?;
    let reset_count = c.u32("clockInfo.resetCount")?;
    let restart_count = c.u32("clockInfo.restartCount")?;
    let safe = c.u8("clockInfo.safe")?;
    let clock_info = TpmsClockInfo {
        clock,
        reset_count,
        restart_count,
        safe,
    };

    let firmware_version = c.u64("firmwareVersion")?;

    // TPMU_ATTEST = TPMS_QUOTE_INFO (since type == ATTEST_QUOTE).
    // TPML_PCR_SELECTION: u32 count || count * TPMS_PCR_SELECTION
    let count = c.u32("pcrSelect.count")? as usize;
    // Sanity ceiling: a real TPM caps this at ~16 banks; reject implausible
    // values to avoid DoS via giant allocations.
    if count > 64 {
        return Err(AttestationError::Malformed(format!(
            "pcrSelect.count={count} exceeds sane upper bound 64"
        )));
    }
    let mut pcr_select = Vec::with_capacity(count);
    for _ in 0..count {
        let hash_alg = c.u16("pcrSelection.hashAlg")?;
        let size_of_select = c.u8("pcrSelection.sizeOfSelect")? as usize;
        // sizeOfSelect maxes at 32 in practice (256 PCRs).
        if size_of_select > 32 {
            return Err(AttestationError::Malformed(format!(
                "pcrSelection.sizeOfSelect={size_of_select} exceeds upper bound 32"
            )));
        }
        let bitmap = c.bytes(size_of_select, "pcrSelection.pcrSelect")?;
        pcr_select.push(TpmsPcrSelection {
            hash_alg,
            pcr_select_bitmap: bitmap,
        });
    }
    let pcr_digest = c.tpm2b("pcrDigest")?;

    // Trailing bytes are unusual but not strictly fatal (some TPM stacks
    // pad). We do not error on remainder — the spec leaves room for vendor
    // extensions. Operators who want a strict policy can compare
    // `c.pos == bytes.len()` themselves.

    Ok(TpmsAttest {
        magic,
        kind,
        qualified_signer,
        extra_data,
        clock_info,
        firmware_version,
        quote: TpmsQuoteInfo {
            pcr_select,
            pcr_digest,
        },
    })
}

/// Verify the AIK signature over the TPMS_ATTEST quote bytes.
///
/// The `signature` argument is the **raw signature bytes** (not a TPMT_SIGNATURE
/// envelope) — operators submit `signature_b64` after stripping the TPM2
/// TPMT_SIGNATURE wrapper, OR alternatively pass the whole TPMT_SIGNATURE and
/// rely on the inferred algorithm from `aik_pubkey`. We accept both shapes:
///
///   - If `aik_pubkey` is `Ed25519`: signature is a raw 64-byte Ed25519 sig.
///   - If `aik_pubkey` is `EcdsaP256`: signature is a 64-byte fixed-width
///     `r || s` (ring's `ECDSA_P256_SHA256_FIXED` shape). TPM2 emits its
///     ECDSA signatures as `(R, S)` big-endian; the operator-side tool
///     should concatenate them.
///   - If `aik_pubkey` is `RsaPkcs1Spki`: signature is the raw RSA PKCS1
///     signature bytes (modulus-length, big-endian).
///
/// `quote_bytes` is the TPMS_ATTEST byte string the TPM signed.
pub fn verify_aik_signature(
    quote_bytes: &[u8],
    signature: &[u8],
    aik_pubkey: &TpmPublicKey,
) -> Result<(), AttestationError> {
    use ::ring::signature as ring_sig;

    match aik_pubkey {
        TpmPublicKey::Ed25519(pk) => {
            let key = ring_sig::UnparsedPublicKey::new(&ring_sig::ED25519, pk);
            key.verify(quote_bytes, signature)
                .map_err(|_| AttestationError::BadSignature)
        }
        TpmPublicKey::EcdsaP256(spki_point) => {
            let key = ring_sig::UnparsedPublicKey::new(
                &ring_sig::ECDSA_P256_SHA256_FIXED,
                spki_point,
            );
            key.verify(quote_bytes, signature)
                .map_err(|_| AttestationError::BadSignature)
        }
        TpmPublicKey::RsaPkcs1Spki(spki_der) => {
            // ring's `RsaPublicKey::from_public_key_der` is gated behind
            // `parse_public_key_der`; the public path is `UnparsedPublicKey`
            // taking an SPKI DER blob.
            let key = ring_sig::UnparsedPublicKey::new(
                &ring_sig::RSA_PKCS1_2048_8192_SHA256,
                spki_der,
            );
            key.verify(quote_bytes, signature)
                .map_err(|_| AttestationError::BadSignature)
        }
    }
}

/// Detect a TPMT_SIGNATURE prefix algorithm. Operators who submit the full
/// `TPMT_SIGNATURE` envelope (rather than raw bytes) can use this to extract
/// the algorithm before stripping the wrapper. Returns `(sig_alg, hash_alg)`.
///
/// TPMT_SIGNATURE layout (spec §11.3):
///   u16 sigAlg || (per-alg signature data)
///   for RSASSA: u16 hash || TPM2B_PUBLIC_KEY_RSA (u16 size || sig bytes)
///   for ECDSA:  u16 hash || TPM2B_ECC_PARAMETER (u16 size || R) || TPM2B_ECC_PARAMETER (u16 size || S)
///   for EDDSA:  u16 hash || TPM2B_ECC_PARAMETER (u16 size || R) || TPM2B_ECC_PARAMETER (u16 size || S)
pub fn detect_tpmt_signature_alg(sig_bytes: &[u8]) -> Result<(u16, u16), AttestationError> {
    if sig_bytes.len() < 4 {
        return Err(AttestationError::Malformed(
            "TPMT_SIGNATURE shorter than 4 bytes; missing sigAlg+hashAlg".into(),
        ));
    }
    let sig_alg = u16::from_be_bytes([sig_bytes[0], sig_bytes[1]]);
    let hash_alg = u16::from_be_bytes([sig_bytes[2], sig_bytes[3]]);
    match sig_alg {
        TPM_ALG_RSASSA | TPM_ALG_ECDSA | TPM_ALG_EDDSA => {}
        other => {
            return Err(AttestationError::Malformed(format!(
                "TPMT_SIGNATURE sigAlg 0x{other:04x} not in {{RSASSA, ECDSA, EDDSA}}; M2 supports only those"
            )));
        }
    }
    match hash_alg {
        TPM_ALG_SHA256 | TPM_ALG_SHA384 | TPM_ALG_SHA1 => {}
        other => {
            return Err(AttestationError::Malformed(format!(
                "TPMT_SIGNATURE hashAlg 0x{other:04x} not in {{SHA1, SHA256, SHA384}}"
            )));
        }
    }
    Ok((sig_alg, hash_alg))
}

/// Walk the AIK certificate up to the EK certificate chain, then to a trusted
/// vendor root. Returns `Ok(())` only when:
///   1. All PEM blocks parse as DER.
///   2. The chain validates per RFC 5280 (webpki).
///   3. The terminal cert chains to one of `trusted_roots`.
///
/// Operators supply roots via [`load_trusted_tpm2_roots`]. When the supplied
/// slice is empty this function returns `PartialImplementation` instructing
/// the operator to configure `SAURON_TPM2_VENDOR_ROOTS_DIR`. We deliberately
/// do NOT bundle commercial vendor roots — the IP/licensing surface (multi-MB
/// Infineon/STMicro/MS/Intel/AMD/IBM CA bundles) is the operator's call.
pub fn verify_aik_cert_chain(
    aik_cert_pem: &str,
    ek_chain_pem: &[&str],
    trusted_roots: &[&[u8]],
) -> Result<(), AttestationError> {
    if trusted_roots.is_empty() {
        return Err(AttestationError::PartialImplementation(
            "no TPM2 vendor roots configured; place vendor DER certs at SAURON_TPM2_VENDOR_ROOTS_DIR (default /etc/sauronid/tpm2-roots/) — see docs/operations.md"
        ));
    }

    // PEM → DER for the AIK end-entity cert.
    let aik_der = pem_to_single_der(aik_cert_pem, "aik_cert_pem")?;

    // Each ek_chain_pem entry may contain one or more concatenated PEM blocks;
    // flatten into a single DER list.
    let mut intermediate_ders: Vec<Vec<u8>> = Vec::new();
    for (i, blob) in ek_chain_pem.iter().enumerate() {
        for cert in pem_to_multi_der(blob, &format!("ek_chain_pem[{i}]"))? {
            intermediate_ders.push(cert);
        }
    }
    let intermediate_refs: Vec<&[u8]> = intermediate_ders.iter().map(|v| v.as_slice()).collect();

    // Build webpki TrustAnchors from operator-supplied DER roots.
    let trust_anchors: Vec<webpki::TrustAnchor<'_>> = trusted_roots
        .iter()
        .enumerate()
        .map(|(i, der)| {
            webpki::TrustAnchor::try_from_cert_der(der).map_err(|e| {
                AttestationError::BadCertChain(format!(
                    "trusted_roots[{i}] not a valid DER trust anchor: {e:?}"
                ))
            })
        })
        .collect::<Result<_, _>>()?;
    let server_trust_anchors = webpki::TlsServerTrustAnchors(&trust_anchors);

    let end_entity = webpki::EndEntityCert::try_from(aik_der.as_slice())
        .map_err(|e| AttestationError::BadCertChain(format!("AIK end-entity parse: {e:?}")))?;

    // We do not have a time source plumbed through; use UNIX time from
    // std::time as a best-effort "now". Operators with a vetted clock source
    // can swap this for a fixed `webpki::Time::from_seconds_since_unix_epoch`.
    let now = webpki::Time::from_seconds_since_unix_epoch(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );

    // TPM AIK certs are TLS-server-cert-shaped in practice (vendor profile
    // varies). webpki 0.22 exposes verify_is_valid_tls_server_cert which is
    // the closest match. Operators with stricter EKU policies should layer
    // their own check on top.
    //
    // webpki 0.22 does not export an `ALL_SIGALGS` constant — assemble the
    // intersection of (RSA-PKCS1, ECDSA, Ed25519) ourselves so any TPM AIK
    // cert signed with a current algorithm validates.
    static SUPPORTED_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
        &webpki::ECDSA_P256_SHA256,
        &webpki::ECDSA_P256_SHA384,
        &webpki::ECDSA_P384_SHA256,
        &webpki::ECDSA_P384_SHA384,
        &webpki::RSA_PKCS1_2048_8192_SHA256,
        &webpki::RSA_PKCS1_2048_8192_SHA384,
        &webpki::RSA_PKCS1_2048_8192_SHA512,
        &webpki::RSA_PKCS1_3072_8192_SHA384,
        &webpki::ED25519,
    ];

    end_entity
        .verify_is_valid_tls_server_cert(
            SUPPORTED_SIGALGS,
            &server_trust_anchors,
            &intermediate_refs,
            now,
        )
        .map_err(|e| {
            AttestationError::BadCertChain(format!(
                "AIK→EK→root chain rejected by webpki: {e:?}"
            ))
        })?;

    Ok(())
}

fn pem_to_single_der(input: &str, field: &str) -> Result<Vec<u8>, AttestationError> {
    let parsed = pem::parse(input.as_bytes()).map_err(|e| {
        AttestationError::Malformed(format!("{field} not valid PEM: {e}"))
    })?;
    Ok(parsed.into_contents())
}

fn pem_to_multi_der(input: &str, field: &str) -> Result<Vec<Vec<u8>>, AttestationError> {
    let parsed = pem::parse_many(input.as_bytes()).map_err(|e| {
        AttestationError::Malformed(format!("{field} not valid PEM: {e}"))
    })?;
    Ok(parsed.into_iter().map(|p| p.into_contents()).collect())
}

/// Load DER trust anchors from the configured directory.
///
/// `SAURON_TPM2_VENDOR_ROOTS_DIR` overrides the default (`/etc/sauronid/tpm2-roots/`).
/// Reads every file with extension `.der`; ignores other files. Returns an
/// empty `Vec` when the directory does not exist or is empty — callers
/// translate that into a `PartialImplementation` operator-facing error.
pub fn load_trusted_tpm2_roots() -> Vec<Vec<u8>> {
    let dir = std::env::var("SAURON_TPM2_VENDOR_ROOTS_DIR")
        .unwrap_or_else(|_| "/etc/sauronid/tpm2-roots/".to_string());
    let path = std::path::Path::new(&dir);
    let read = match std::fs::read_dir(path) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for entry in read.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("der") {
            if let Ok(bytes) = std::fs::read(&p) {
                out.push(bytes);
            }
        }
    }
    out
}

/// Compare the parsed quote's PCR digest against the operator-supplied
/// expected measurement. Constant-time comparison to avoid leaking the
/// position of a divergence via timing.
pub fn verify_pcr_digest(
    parsed: &TpmsAttest,
    expected_pcr_digest_hex: &str,
) -> Result<(), AttestationError> {
    let expected = hex::decode(expected_pcr_digest_hex.trim()).map_err(|e| {
        AttestationError::Malformed(format!(
            "expected_pcr_digest_hex is not valid hex: {e}"
        ))
    })?;
    if expected.len() != parsed.quote.pcr_digest.len() {
        return Err(AttestationError::MeasurementMismatch {
            expected: hex::encode(&expected),
            got: hex::encode(&parsed.quote.pcr_digest),
        });
    }
    if parsed
        .quote
        .pcr_digest
        .as_slice()
        .ct_eq(expected.as_slice())
        .unwrap_u8()
        == 1
    {
        Ok(())
    } else {
        Err(AttestationError::MeasurementMismatch {
            expected: hex::encode(&expected),
            got: hex::encode(&parsed.quote.pcr_digest),
        })
    }
}

/// Full M2 verifier flow for a TPM2 quote:
///
///   1. Parse Tpm2QuotePayload (operator-submitted JSON).
///   2. Parse TPMS_ATTEST bytes (magic, type, quote info).
///   3. Compare pcrDigest against ctx.expected_measurement_hex.
///   4. Walk AIK→EK→root cert chain (operator-supplied vendor roots).
///   5. Verify the AIK signature over the TPMS_ATTEST bytes.
///
/// Short-circuits on the first failure. If the operator has not configured
/// vendor roots (`SAURON_TPM2_VENDOR_ROOTS_DIR` empty/missing) we return
/// `PartialImplementation` with the config instruction — strictly more
/// informative than the M1 stub, and prevents silent acceptance of an
/// unrooted chain.
fn verify_tpm2_quote(blob: &[u8], ctx: &AttestationContext) -> Result<(), AttestationError> {
    use base64::engine::general_purpose::STANDARD as B64;

    // Step 1: structural parse of the operator submission.
    let payload = Tpm2QuotePayload::parse_json(blob)?;

    // Decode base64 fields.
    let attest_bytes = B64.decode(payload.attest_b64.as_bytes()).map_err(|e| {
        AttestationError::Malformed(format!("attest_b64 decode: {e}"))
    })?;
    let signature_bytes = B64.decode(payload.signature_b64.as_bytes()).map_err(|e| {
        AttestationError::Malformed(format!("signature_b64 decode: {e}"))
    })?;

    // Step 2: parse the TPMS_ATTEST structure.
    let parsed = parse_tpms_attest(&attest_bytes)?;

    // Step 3: PCR digest match. We treat `ctx.expected_measurement_hex` as the
    // hex of the expected pcrDigest — operators register this once and the
    // verifier rejects any quote whose composite PCR digest drifts.
    verify_pcr_digest(&parsed, ctx.expected_measurement_hex)?;

    // Step 4: cert chain. Operator supplies vendor roots through the
    // configured dir; M2 deliberately ships no commercial roots.
    let roots = load_trusted_tpm2_roots();
    let roots_refs: Vec<&[u8]> = roots.iter().map(|v| v.as_slice()).collect();
    let ek_chain_one = [payload.ek_cert_chain_pem.as_str()];
    verify_aik_cert_chain(
        payload.aik_cert_pem.as_str(),
        &ek_chain_one,
        &roots_refs,
    )?;

    // Step 5: AIK signature over the TPMS_ATTEST bytes. We require the
    // operator to register the AIK pubkey separately (ctx.trusted_pubkey_b64u)
    // until M3 extracts it from the AIK cert directly. The b64u key encodes
    // a tagged byte string: `ed25519:<32 bytes>` or `p256:<65 bytes>` or
    // `rsa:<spki DER>`. Operators on M2 typically use Ed25519.
    let aik_pubkey = parse_trusted_pubkey(ctx.trusted_pubkey_b64u)?;
    verify_aik_signature(&attest_bytes, &signature_bytes, &aik_pubkey)?;

    Ok(())
}

/// Decode an operator-registered AIK pubkey. Format:
///
///   "ed25519:<base64url of 32 raw bytes>"
///   "p256:<base64url of 65-byte SEC1 uncompressed point>"
///   "rsa:<base64url of SPKI DER>"
///
/// We use a tag prefix rather than auto-detecting because raw 32-byte material
/// could be either an Ed25519 point or a degenerate ECDSA value; explicit is
/// safer than clever.
fn parse_trusted_pubkey(s: &str) -> Result<TpmPublicKey, AttestationError> {
    let (tag, b64) = s.split_once(':').ok_or_else(|| {
        AttestationError::BadCertChain(
            "trusted_pubkey_b64u missing 'ed25519:|p256:|rsa:' tag prefix".into(),
        )
    })?;
    let bytes = URL_SAFE_NO_PAD
        .decode(b64.trim())
        .map_err(|e| AttestationError::BadCertChain(format!("trusted_pubkey_b64u decode: {e}")))?;
    match tag {
        "ed25519" => {
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| AttestationError::BadCertChain("ed25519 key is not 32 bytes".into()))?;
            Ok(TpmPublicKey::Ed25519(arr))
        }
        "p256" => {
            if bytes.len() != 65 || bytes[0] != 0x04 {
                return Err(AttestationError::BadCertChain(
                    "p256 key must be 65-byte SEC1 uncompressed (0x04 || X || Y)".into(),
                ));
            }
            Ok(TpmPublicKey::EcdsaP256(bytes))
        }
        "rsa" => Ok(TpmPublicKey::RsaPkcs1Spki(bytes)),
        other => Err(AttestationError::BadCertChain(format!(
            "unknown trusted_pubkey tag '{other}', expected ed25519|p256|rsa"
        ))),
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
        // M1 of the TPM2 roadmap: `Tpm2Quote` is no longer `NotImplemented` — it
        // returns `Malformed` for garbage input and `PartialImplementation` for
        // well-formed input. The other hardware kinds remain `NotImplemented`
        // until their respective milestones land.
        let ctx = AttestationContext {
            expected_measurement_hex: "x",
            trusted_pubkey_b64u: "x",
        };
        for k in [
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

    // ── M1 of TPM2 PoP roadmap ───────────────────────────────────────────────

    fn well_formed_tpm2_payload() -> Vec<u8> {
        use base64::engine::general_purpose::STANDARD as B64;
        let cert_pem = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALxk\n-----END CERTIFICATE-----\n";
        serde_json::json!({
            "quote_b64": B64.encode(b"fake-quote-bytes"),
            "attest_b64": B64.encode(b"fake-attest-bytes"),
            "signature_b64": B64.encode(b"fake-signature-bytes"),
            "aik_cert_pem": cert_pem,
            "ek_cert_chain_pem": cert_pem,
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn tpm2_quote_returns_malformed_when_attest_bytes_garbage() {
        // M2 contract: the JSON wrapper parses (well-formed shape) but the
        // base64-decoded attest payload fails the TPMS_ATTEST magic check —
        // every real TPM-generated quote starts with 0xff544347. We now
        // surface that as `Malformed` rather than the old M1 stub return.
        // This test used to assert `PartialImplementation` (M1); the M2
        // verifier reaches further into the blob so the contract tightens.
        let blob = well_formed_tpm2_payload();
        let ctx = AttestationContext {
            expected_measurement_hex: "x",
            trusted_pubkey_b64u: "ed25519:x",
        };
        match verify_attestation(AttestationKind::Tpm2Quote, &blob, &ctx) {
            Err(AttestationError::Malformed(msg)) => {
                assert!(
                    msg.contains("TPM_GENERATED_VALUE") || msg.contains("magic"),
                    "expected magic-check failure, got: {msg}"
                );
            }
            other => panic!(
                "expected Malformed for fake TPMS_ATTEST bytes, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn tpm2_quote_returns_malformed_on_missing_field() {
        let blob = serde_json::json!({
            "quote_b64": "QQ==",
            // attest_b64 missing
            "signature_b64": "QQ==",
            "aik_cert_pem": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
            "ek_cert_chain_pem": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        })
        .to_string()
        .into_bytes();
        let ctx = AttestationContext {
            expected_measurement_hex: "x",
            trusted_pubkey_b64u: "x",
        };
        match verify_attestation(AttestationKind::Tpm2Quote, &blob, &ctx) {
            Err(AttestationError::Malformed(_)) => {}
            other => panic!("expected Malformed for missing field, got {:?}", other),
        }
    }

    #[test]
    fn tpm2_quote_returns_malformed_on_bad_base64() {
        let blob = serde_json::json!({
            "quote_b64": "@@@@",
            "attest_b64": "QQ==",
            "signature_b64": "QQ==",
            "aik_cert_pem": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
            "ek_cert_chain_pem": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        })
        .to_string()
        .into_bytes();
        let ctx = AttestationContext {
            expected_measurement_hex: "x",
            trusted_pubkey_b64u: "x",
        };
        match verify_attestation(AttestationKind::Tpm2Quote, &blob, &ctx) {
            Err(AttestationError::Malformed(_)) => {}
            other => panic!("expected Malformed for bad base64, got {:?}", other),
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
        // M1 contract: ServerDerived PoP is refused when ENV=production and
        // SAURON_ALLOW_SERVER_DERIVED_POP is not set. This is the security
        // upgrade — the previous default silently accepted server-derived keys.
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
        // M1 contract: setting SAURON_ALLOW_SERVER_DERIVED_POP=1 lets the
        // operator opt back into the legacy default. This keeps existing
        // deployments working during the upgrade window.
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
        // M1 contract: development runtime keeps the old behaviour so existing
        // test scenarios and local demos keep working without modification.
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

    // ── M2 of TPM2 PoP roadmap ───────────────────────────────────────────────
    // Real TPMS_ATTEST parser + AIK signature verification + cert-chain
    // skeleton. Fixtures are synthesised in-process: we hand-build the TPM
    // binary structures byte-for-byte so the tests stay deterministic and
    // do not depend on a real TPM device.

    /// Build a minimal valid TPMS_ATTEST byte stream for a quote attestation.
    /// `pcr_digest` is hex-decoded and embedded as the pcrDigest field.
    fn build_tpms_attest(pcr_digest_hex: &str) -> Vec<u8> {
        let pcr_digest = hex::decode(pcr_digest_hex).unwrap();
        let mut out = Vec::new();
        // magic = TPM_GENERATED_VALUE
        out.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        // type = TPM_ST_ATTEST_QUOTE
        out.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        // qualifiedSigner: TPM2B_NAME (len=2 + 2 bytes "AA")
        out.extend_from_slice(&2u16.to_be_bytes());
        out.extend_from_slice(b"AA");
        // extraData: TPM2B_DATA (len=4 + 4 bytes nonce)
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        // clockInfo: u64 clock + u32 reset + u32 restart + u8 safe
        out.extend_from_slice(&1_000u64.to_be_bytes());
        out.extend_from_slice(&7u32.to_be_bytes());
        out.extend_from_slice(&3u32.to_be_bytes());
        out.push(1);
        // firmwareVersion
        out.extend_from_slice(&0x4242_4242_4242_4242u64.to_be_bytes());
        // pcrSelect: TPML_PCR_SELECTION
        //   count=1
        out.extend_from_slice(&1u32.to_be_bytes());
        //   TPMS_PCR_SELECTION: u16 hashAlg=SHA256 || u8 sizeOfSelect=3 || 3 bytes bitmap
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.push(3);
        // PCR bitmap: PCRs 0,1,7 selected → bits in little-endian-per-byte
        out.extend_from_slice(&[0b1000_0011, 0x00, 0x00]);
        // pcrDigest: TPM2B_DIGEST
        out.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
        out.extend_from_slice(&pcr_digest);
        out
    }

    #[test]
    fn parse_tpms_attest_valid_quote() {
        // 32-byte SHA-256-shaped digest.
        let pcr_hex = "a".repeat(64);
        let bytes = build_tpms_attest(&pcr_hex);
        let parsed = parse_tpms_attest(&bytes).expect("valid quote should parse");
        assert_eq!(parsed.magic, TPM_GENERATED_VALUE);
        assert_eq!(parsed.kind, TPM_ST_ATTEST_QUOTE);
        assert_eq!(parsed.qualified_signer, b"AA");
        assert_eq!(parsed.extra_data, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parsed.clock_info.clock, 1_000);
        assert_eq!(parsed.clock_info.reset_count, 7);
        assert_eq!(parsed.clock_info.restart_count, 3);
        assert_eq!(parsed.clock_info.safe, 1);
        assert_eq!(parsed.firmware_version, 0x4242_4242_4242_4242);
        assert_eq!(parsed.quote.pcr_select.len(), 1);
        assert_eq!(parsed.quote.pcr_select[0].hash_alg, TPM_ALG_SHA256);
        assert_eq!(parsed.quote.pcr_select[0].pcr_select_bitmap.len(), 3);
        assert_eq!(parsed.quote.pcr_digest, hex::decode(&pcr_hex).unwrap());
    }

    #[test]
    fn parse_tpms_attest_rejects_bad_magic() {
        let mut bytes = build_tpms_attest(&"00".repeat(32));
        // Corrupt the magic.
        bytes[0..4].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        match parse_tpms_attest(&bytes) {
            Err(AttestationError::Malformed(msg)) => {
                assert!(msg.contains("magic"), "expected magic-related error, got: {msg}");
            }
            other => panic!("expected Malformed on bad magic, got {:?}", other),
        }
    }

    #[test]
    fn parse_tpms_attest_rejects_bad_type() {
        let mut bytes = build_tpms_attest(&"00".repeat(32));
        // Corrupt the type field (bytes 4..6) to an arbitrary non-quote value.
        bytes[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        match parse_tpms_attest(&bytes) {
            Err(AttestationError::Malformed(msg)) => {
                assert!(
                    msg.contains("type") || msg.contains("ATTEST_QUOTE"),
                    "expected type-related error, got: {msg}"
                );
            }
            other => panic!("expected Malformed on bad type, got {:?}", other),
        }
    }

    #[test]
    fn tpm2b_rejects_oversized_length_no_panic_no_alloc() {
        // H3 regression: feed a TPMS_ATTEST whose first TPM2B field
        // (`qualifiedSigner`) declares length 0xFFFF (~64 KiB) against a tiny
        // ~100-byte buffer. Pre-fix this could attempt a large pre-allocation
        // before bounds-checking. Post-fix it must short-circuit with
        // Malformed referencing the bogus length.
        //
        // Layout up to that field: magic(4) || type(2) || qualifiedSigner.len(2)
        // = 8 bytes of header before the oversized declared length kicks in.
        let mut bytes = Vec::with_capacity(100);
        bytes.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes()); // valid magic
        bytes.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes()); // valid type
        bytes.extend_from_slice(&0xFFFFu16.to_be_bytes()); // qualifiedSigner length = 65535
        // Pad to exactly 100 bytes total so remaining < declared length.
        bytes.resize(100, 0x00);

        match parse_tpms_attest(&bytes) {
            Err(AttestationError::Malformed(msg)) => {
                assert!(
                    msg.contains("qualifiedSigner") && msg.contains("65535"),
                    "expected qualifiedSigner/65535-related error, got: {msg}"
                );
                assert!(
                    msg.contains("exceeds remaining buffer")
                        || msg.contains("truncated"),
                    "expected explicit remaining-buffer diagnostic, got: {msg}"
                );
            }
            other => panic!(
                "expected Malformed for oversized TPM2B length, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn verify_pcr_digest_matches() {
        let pcr_hex = "1122334455667788aabbccddeeff00112233445566778899aabbccddeeff0011";
        let bytes = build_tpms_attest(pcr_hex);
        let parsed = parse_tpms_attest(&bytes).unwrap();
        verify_pcr_digest(&parsed, pcr_hex).expect("matching digest should pass");
    }

    #[test]
    fn verify_pcr_digest_mismatch() {
        let bytes = build_tpms_attest(&"aa".repeat(32));
        let parsed = parse_tpms_attest(&bytes).unwrap();
        match verify_pcr_digest(&parsed, &"bb".repeat(32)) {
            Err(AttestationError::MeasurementMismatch { .. }) => {}
            other => panic!("expected MeasurementMismatch, got {:?}", other),
        }
    }

    #[test]
    fn verify_aik_signature_ed25519_success_and_failure() {
        use ed25519_dalek::Signer;
        let mut csprng = rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk_bytes = sk.verifying_key().to_bytes();
        let pubkey = TpmPublicKey::Ed25519(pk_bytes);

        let quote = build_tpms_attest(&"cc".repeat(32));
        let sig = sk.sign(&quote);
        // Success path: matching key + matching message.
        verify_aik_signature(&quote, &sig.to_bytes(), &pubkey)
            .expect("ed25519 round-trip should verify");

        // Failure path: tamper one byte of the message.
        let mut tampered = quote.clone();
        tampered[10] ^= 0xff;
        match verify_aik_signature(&tampered, &sig.to_bytes(), &pubkey) {
            Err(AttestationError::BadSignature) => {}
            other => panic!("expected BadSignature on tampered message, got {:?}", other),
        }

        // Failure path: wrong key.
        let other_sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let other_pk = TpmPublicKey::Ed25519(other_sk.verifying_key().to_bytes());
        match verify_aik_signature(&quote, &sig.to_bytes(), &other_pk) {
            Err(AttestationError::BadSignature) => {}
            other => panic!("expected BadSignature on wrong key, got {:?}", other),
        }
    }

    #[test]
    fn verify_aik_signature_ecdsa_p256_round_trip() {
        use ::ring::rand::SystemRandom;
        use ::ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let pubkey_bytes = kp.public_key().as_ref().to_vec();
        let pubkey = TpmPublicKey::EcdsaP256(pubkey_bytes);

        let quote = build_tpms_attest(&"ee".repeat(32));
        let sig = kp.sign(&rng, &quote).unwrap();
        verify_aik_signature(&quote, sig.as_ref(), &pubkey)
            .expect("ecdsa-p256 round-trip should verify");

        // Tamper signature.
        let mut bad_sig = sig.as_ref().to_vec();
        bad_sig[0] ^= 0xff;
        match verify_aik_signature(&quote, &bad_sig, &pubkey) {
            Err(AttestationError::BadSignature) => {}
            other => panic!("expected BadSignature, got {:?}", other),
        }
    }

    #[test]
    fn verify_aik_cert_chain_returns_partial_when_no_roots() {
        // Operator has not configured vendor roots (empty trusted_roots).
        // Contract: PartialImplementation with the SAURON_TPM2_VENDOR_ROOTS_DIR
        // instruction, NOT a silent accept.
        let cert_pem = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALxk\n-----END CERTIFICATE-----\n";
        let res = verify_aik_cert_chain(cert_pem, &[cert_pem], &[]);
        match res {
            Err(AttestationError::PartialImplementation(msg)) => {
                assert!(
                    msg.contains("SAURON_TPM2_VENDOR_ROOTS_DIR"),
                    "msg should name the config var, got: {msg}"
                );
            }
            other => panic!(
                "expected PartialImplementation with config instruction, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn verify_aik_cert_chain_rejects_unrooted_chain_when_roots_configured() {
        // Operator configured some roots (synthetic garbage DER), but the
        // supplied AIK does not chain to them. Contract: BadCertChain (not
        // a silent accept, not a PartialImplementation).
        let aik_pem = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALxk\n-----END CERTIFICATE-----\n";
        // 64 bytes of structured-but-bogus "DER" — webpki will reject as a
        // trust anchor, which we surface as BadCertChain.
        let synthetic_root = vec![0x30u8; 64];
        let res = verify_aik_cert_chain(
            aik_pem,
            &[aik_pem],
            &[synthetic_root.as_slice()],
        );
        match res {
            Err(AttestationError::BadCertChain(_)) => {}
            other => panic!(
                "expected BadCertChain when roots present but chain invalid, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn parse_trusted_pubkey_accepts_tagged_ed25519() {
        let mut csprng = rand::rngs::OsRng;
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let pk_b64u = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let tagged = format!("ed25519:{pk_b64u}");
        match parse_trusted_pubkey(&tagged).unwrap() {
            TpmPublicKey::Ed25519(_) => {}
            other => panic!("expected Ed25519 variant, got {:?}", other),
        }
    }
}

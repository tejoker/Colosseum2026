//! Server-side verifier for action-log ZK proofs (Sprint 4).
//!
//! ## Dependency choice
//!
//! Two implementation paths were considered:
//!   1. Direct verification via `ark-groth16` + `ark-bn254`.
//!   2. Spawn `snarkjs verify` as a subprocess.
//!
//! Choice: **subprocess spawn** for M1. Rationale:
//!   - Adding `ark-*` pulls ~20 transitive crates and BN254-pairing code, which
//!     materially grows the binary and tightens our supply-chain surface.
//!   - The snarkjs binary is already an SDK dep; reusing it keeps the prover
//!     and verifier on byte-identical verification semantics.
//!   - For M1, latency (~80–200ms per call) is acceptable: action-log proofs
//!     are batched on submission, not on the hot path of every API request.
//!   - Migrating to in-process `ark-groth16` is a backlog item once we ship
//!     real ceremony keys; the spawn shim is hidden behind one trait.
//!
//! Production deployments MUST replace the DEV verification keys
//! (`*.dev.vkey.json`) with keys produced by a real multi-party trusted setup
//! ceremony (see `zkp/ceremony/README.md`).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

// ════════════════════════════════════════════════════════════════════════
// Public types
// ════════════════════════════════════════════════════════════════════════

/// JSON payload posted by the SDK to the action-log verify endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLogProofPayload {
    /// Circuit name; matches the file stem of the verification key
    /// (`{circuit}.dev.vkey.json` for the DEV keys we ship in M1).
    pub circuit: String,
    /// Canonical snarkjs public-signals array, base-10 strings.
    pub public_inputs: Vec<String>,
    /// Base64-encoded JSON of the snarkjs Groth16 proof object
    /// (`{pi_a, pi_b, pi_c, protocol, curve}`).
    pub proof_b64: String,
    /// Verification key identifier — used for key-rotation observability.
    /// Format: `{circuit}.dev.vk@v{N}` for DEV, `{circuit}.vk@v{N}` for prod.
    pub vk_id: String,
}

/// Result type for verification failures.
#[derive(Debug)]
pub enum ZkVerifyError {
    Malformed(String),
    KeyNotFound(String),
    VerifierFailed(String),
    Invalid(String),
}

impl fmt::Display for ZkVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZkVerifyError::Malformed(s) => write!(f, "malformed payload: {s}"),
            ZkVerifyError::KeyNotFound(s) => write!(f, "verification key missing: {s}"),
            ZkVerifyError::VerifierFailed(s) => write!(f, "verifier process failed: {s}"),
            ZkVerifyError::Invalid(s) => write!(f, "proof rejected: {s}"),
        }
    }
}

impl std::error::Error for ZkVerifyError {}

/// Loads verification keys from a directory. Trait-shaped so tests can stub.
pub trait VKeyLoader: Send + Sync {
    /// Returns the absolute path to the verification key JSON file for the
    /// given circuit, or `Err` if it's missing.
    fn vkey_path(&self, circuit: &str) -> Result<PathBuf, ZkVerifyError>;
}

/// Default loader rooted at `zkp/circuits/build/keys` (DEV keys).
#[derive(Debug, Clone)]
pub struct FsVKeyLoader {
    pub root_dir: PathBuf,
}

impl FsVKeyLoader {
    pub fn new<P: Into<PathBuf>>(p: P) -> Self {
        Self { root_dir: p.into() }
    }
}

impl VKeyLoader for FsVKeyLoader {
    fn vkey_path(&self, circuit: &str) -> Result<PathBuf, ZkVerifyError> {
        // DEV layout first (Sprint 4), fall back to legacy layout for old circuits.
        let dev = self.root_dir.join(format!("{circuit}.dev.vkey.json"));
        if dev.is_file() {
            return Ok(dev);
        }
        let legacy = self
            .root_dir
            .join(format!("{circuit}_verification_key.json"));
        if legacy.is_file() {
            return Ok(legacy);
        }
        Err(ZkVerifyError::KeyNotFound(format!(
            "neither {} nor {} exist",
            dev.display(),
            legacy.display()
        )))
    }
}

// ════════════════════════════════════════════════════════════════════════
// Public API
// ════════════════════════════════════════════════════════════════════════

/// Verifies an action-log proof and that its public root matches the expected
/// hex-encoded Merkle root.
///
/// `expected_root_hex` is the action-log Merkle root the verifier expects to
/// see committed in the proof's public signals. By convention, every action-log
/// circuit places the root at `public_inputs[0]` (snarkjs orders outputs first,
/// then publicly declared inputs in the order of the `main` declaration; all
/// our action-log circuits declare `root` as the first public input and have
/// exactly one output `valid` so the structure is:
///   `public_inputs = [valid, root, ...rest]`).
///
/// The check matches `expected_root_hex` against the *decimal* `public_inputs[1]`
/// converted to a 32-byte big-endian hex string. This decouples the API caller
/// from the field-element representation produced by snarkjs.
pub async fn verify_action_log_proof<L: VKeyLoader>(
    payload: &ActionLogProofPayload,
    expected_root_hex: &str,
    vk_loader: &L,
) -> Result<(), ZkVerifyError> {
    // Sanity-validate the payload, then resolve the vkey path through the
    // loader, then delegate to the explicit-vk variant. Tests can call the
    // explicit variant directly when they want to point at a specific
    // committed DEV key without going through the FS loader.
    validate_payload_shape(payload)?;
    let vkey_path = vk_loader.vkey_path(&payload.circuit)?;
    verify_action_log_proof_with_vk(payload, expected_root_hex, &vkey_path).await
}

/// Verifies an action-log proof against an explicit verification-key path.
///
/// This is the lower-level entry point used by [`verify_action_log_proof`]
/// (which resolves the path via a [`VKeyLoader`]) and by tests that ship
/// pre-located DEV keys in `zkp/circuits/build/keys/`.
///
/// Fail-closed contract for production: when the loaded vk JSON contains the
/// `_disclaimer` field AND the runtime environment is production (i.e.
/// [`crate::runtime_mode::is_development_runtime`] is false), verification is
/// refused with [`ZkVerifyError::KeyNotFound`] — the operator MUST replace the
/// DEV key with a real-ceremony key before the verifier will accept any
/// proof under that circuit. Development runtimes pass through with a
/// `[WARN] using DEV verification key` log line.
pub async fn verify_action_log_proof_with_vk(
    payload: &ActionLogProofPayload,
    expected_root_hex: &str,
    vkey_path: &Path,
) -> Result<(), ZkVerifyError> {
    validate_payload_shape(payload)?;

    // Public-root binding (decimal public_inputs[1] → 32-byte hex).
    let claimed_root_dec = payload.public_inputs[1].trim();
    let expected_root_hex = expected_root_hex
        .trim()
        .trim_start_matches("0x")
        .to_lowercase();
    let claimed_root_hex = decimal_to_padded_hex(claimed_root_dec)
        .map_err(|e| ZkVerifyError::Malformed(format!("bad root encoding: {e}")))?;
    if claimed_root_hex != expected_root_hex {
        return Err(ZkVerifyError::Invalid(format!(
            "proof root {claimed_root_hex} ≠ expected root {expected_root_hex}"
        )));
    }

    // Decode proof JSON
    use base64::Engine;
    let proof_json_bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload.proof_b64)
        .map_err(|e| ZkVerifyError::Malformed(format!("proof_b64 decode: {e}")))?;
    let proof_json: serde_json::Value = serde_json::from_slice(&proof_json_bytes)
        .map_err(|e| ZkVerifyError::Malformed(format!("proof JSON parse: {e}")))?;
    if !proof_json.is_object() {
        return Err(ZkVerifyError::Malformed("proof JSON is not an object".into()));
    }

    // Read the vkey file + check the DEV-disclaimer fail-closed gate.
    let vkey_bytes = std::fs::read(vkey_path)
        .map_err(|e| ZkVerifyError::KeyNotFound(format!("read {}: {e}", vkey_path.display())))?;
    enforce_dev_vkey_policy(&vkey_bytes, vkey_path, &payload.circuit)?;

    // Spawn `snarkjs groth16 verify` — see the module-level doc comment for
    // the dep-choice rationale. Public-inputs + proof go via temp files
    // (snarkjs CLI requires file paths, not stdin).
    let tmp = tempdir_or_err()?;
    let pub_path = tmp.join("public.json");
    let proof_path = tmp.join("proof.json");
    let public_json = serde_json::to_vec(&payload.public_inputs)
        .map_err(|e| ZkVerifyError::Malformed(format!("re-encode public: {e}")))?;
    std::fs::write(&pub_path, &public_json)
        .map_err(|e| ZkVerifyError::VerifierFailed(format!("write public.json: {e}")))?;
    std::fs::write(&proof_path, &proof_json_bytes)
        .map_err(|e| ZkVerifyError::VerifierFailed(format!("write proof.json: {e}")))?;

    let output = tokio::process::Command::new("snarkjs")
        .arg("groth16")
        .arg("verify")
        .arg(vkey_path)
        .arg(&pub_path)
        .arg(&proof_path)
        .output()
        .await
        .map_err(|e| ZkVerifyError::VerifierFailed(format!("spawn snarkjs: {e}")))?;

    let _ = std::fs::remove_file(&pub_path);
    let _ = std::fs::remove_file(&proof_path);
    let _ = std::fs::remove_dir(&tmp);

    if !output.status.success() {
        return Err(ZkVerifyError::Invalid(format!(
            "snarkjs verify exited {} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // snarkjs 0.7 prints "[INFO] snarkJS: OK!" on stderr (not stdout) for
    // valid proofs and "snarkJS: Invalid proof" for rejection. Accept either
    // stream so we stay tolerant of the CLI's output-routing churn.
    let combined = format!("{stdout}{stderr}");
    let lower = combined.to_lowercase();
    if lower.contains("invalid proof") {
        Err(ZkVerifyError::Invalid(format!(
            "snarkjs verify reported invalid proof: {combined}"
        )))
    } else if lower.contains("ok!") || combined.contains("Verified") {
        Ok(())
    } else {
        Err(ZkVerifyError::Invalid(format!(
            "snarkjs verify did not report OK: {combined}"
        )))
    }
}

// Public-payload sanity checks shared by both entry points.
fn validate_payload_shape(payload: &ActionLogProofPayload) -> Result<(), ZkVerifyError> {
    if payload.circuit.is_empty() {
        return Err(ZkVerifyError::Malformed("circuit field is empty".into()));
    }
    if payload.public_inputs.is_empty() {
        return Err(ZkVerifyError::Malformed(
            "public_inputs must not be empty".into(),
        ));
    }
    if payload.proof_b64.is_empty() {
        return Err(ZkVerifyError::Malformed(
            "proof_b64 must not be empty".into(),
        ));
    }
    // Reject obvious payload-injection attempts (path traversal / shell chars
    // in the circuit name — it is used as a filename component).
    if payload
        .circuit
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-' && c != '.')
    {
        return Err(ZkVerifyError::Malformed(format!(
            "circuit name has invalid chars: {}",
            payload.circuit
        )));
    }
    if payload.public_inputs.len() < 2 {
        return Err(ZkVerifyError::Malformed(
            "expected at least [valid, root, ...] public_inputs".into(),
        ));
    }
    Ok(())
}

/// Enforce the DEV-vs-production policy on a verification key JSON.
///
/// In development runtimes (`ENV=development|dev|local`) a vk carrying the
/// `_disclaimer` field is allowed, but we log a clear `[WARN]` so it is
/// visible in operator output. In any other runtime (i.e. production) we
/// fail-closed: a vk with `_disclaimer` is rejected. The matching error
/// instructs the operator to swap in a real-ceremony key.
fn enforce_dev_vkey_policy(
    vkey_bytes: &[u8],
    vkey_path: &Path,
    circuit: &str,
) -> Result<(), ZkVerifyError> {
    let parsed: serde_json::Value = match serde_json::from_slice(vkey_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(()), // malformed vk — snarkjs will reject below
    };
    let has_disclaimer = parsed
        .get("_disclaimer")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.to_ascii_uppercase().contains("DEV ONLY"));
    if !has_disclaimer {
        return Ok(());
    }
    if crate::runtime_mode::is_development_runtime() {
        warn_dev_key_once(circuit, vkey_path);
        Ok(())
    } else {
        Err(ZkVerifyError::KeyNotFound(format!(
            "refusing to use DEV verification key in production runtime: {} \
             (circuit {circuit}). Replace with a real multi-party ceremony \
             key — see zkp/ceremony/README.md.",
            vkey_path.display()
        )))
    }
}

// One log line per (circuit, path) — avoid spamming production-like staging
// envs where ENV=development is intentional. Best-effort; if the once-cell
// fails we still emit the line.
fn warn_dev_key_once(circuit: &str, vkey_path: &Path) {
    use std::sync::OnceLock;
    static SEEN: OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let key = format!("{circuit}:{}", vkey_path.display());
    if let Ok(mut guard) = seen.lock() {
        if guard.insert(key) {
            tracing::warn!(
                target: "sauron::zk_verifier",
                circuit = circuit,
                vkey = %vkey_path.display(),
                "[WARN] using DEV verification key for circuit {circuit} — production must rotate after real ceremony"
            );
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════

fn decimal_to_padded_hex(dec: &str) -> Result<String, String> {
    // Parse decimal big integer using only the std/hex crates already in use.
    // Field elements fit in 32 bytes; we left-pad with zeroes.
    if dec.is_empty() || !dec.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("not a base-10 unsigned integer: {dec}"));
    }
    // Simple repeated *10 + digit over a 32-byte big-endian buffer.
    let mut buf = [0u8; 32];
    for ch in dec.chars() {
        let d = (ch as u8) - b'0';
        let mut carry = d as u16;
        for byte in buf.iter_mut().rev() {
            let prod = (*byte as u16) * 10 + carry;
            *byte = (prod & 0xff) as u8;
            carry = prod >> 8;
        }
        if carry != 0 {
            return Err("value exceeds 32 bytes".into());
        }
    }
    Ok(hex::encode(buf))
}

fn tempdir_or_err() -> Result<PathBuf, ZkVerifyError> {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = base.join(format!("sauron-zk-{pid}-{nonce}"));
    std::fs::create_dir_all(&dir)
        .map_err(|e| ZkVerifyError::VerifierFailed(format!("create tmp: {e}")))?;
    Ok(dir)
}

// ════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub loader that always returns a fixed path; used so we can assert
    /// the verifier's payload-validation logic without an actual vkey file.
    struct StubLoader {
        path: PathBuf,
    }
    impl VKeyLoader for StubLoader {
        fn vkey_path(&self, _circuit: &str) -> Result<PathBuf, ZkVerifyError> {
            if self.path.as_os_str().is_empty() {
                Err(ZkVerifyError::KeyNotFound("stub".into()))
            } else {
                Ok(self.path.clone())
            }
        }
    }

    fn payload(circuit: &str, public_inputs: Vec<&str>, proof: &str) -> ActionLogProofPayload {
        use base64::Engine;
        ActionLogProofPayload {
            circuit: circuit.into(),
            public_inputs: public_inputs.into_iter().map(|s| s.to_string()).collect(),
            proof_b64: base64::engine::general_purpose::STANDARD.encode(proof.as_bytes()),
            vk_id: format!("{circuit}.dev.vk@v0"),
        }
    }

    #[tokio::test]
    async fn malformed_payload_circuit_chars_rejected() {
        let p = payload("../../etc/passwd", vec!["1", "0"], "{}");
        let r = verify_action_log_proof(
            &p,
            &"00".repeat(32),
            &StubLoader {
                path: PathBuf::new(),
            },
        )
        .await;
        assert!(matches!(r, Err(ZkVerifyError::Malformed(_))));
    }

    #[tokio::test]
    async fn root_mismatch_rejected() {
        // public_inputs = ["1" (valid), "42" (root)] → "42" hex-padded ≠ all-FF
        let p = payload("ActionSumBound", vec!["1", "42"], "{}");
        let r = verify_action_log_proof(
            &p,
            &"ff".repeat(32),
            &StubLoader {
                path: PathBuf::from("/tmp/never-exists.vkey.json"),
            },
        )
        .await;
        assert!(matches!(r, Err(ZkVerifyError::Invalid(msg)) if msg.contains("root")));
    }

    #[tokio::test]
    async fn empty_public_inputs_rejected() {
        let p = payload("ActionSumBound", vec![], "{}");
        let r = verify_action_log_proof(
            &p,
            &"00".repeat(32),
            &StubLoader {
                path: PathBuf::from("/tmp/never-exists.vkey.json"),
            },
        )
        .await;
        assert!(matches!(r, Err(ZkVerifyError::Malformed(_))));
    }

    #[test]
    fn decimal_to_hex_roundtrip() {
        assert_eq!(decimal_to_padded_hex("0").unwrap(), "00".repeat(32));
        assert_eq!(
            decimal_to_padded_hex("255").unwrap(),
            format!("{}ff", "00".repeat(31))
        );
        assert!(decimal_to_padded_hex("abc").is_err());
    }

    #[test]
    fn dev_disclaimer_rejected_in_production() {
        // Build an in-memory vk JSON with the DEV disclaimer; force ENV=production
        // by ensuring is_development_runtime() returns false (it defaults to
        // "production" when ENV is unset). Note: we deliberately do NOT set
        // SAURON_ENV here, since this test relies on the default fail-closed
        // behaviour. If a parallel test sets ENV=dev this assertion would
        // become a no-op; the lib-level test suite does not set ENV today.
        let vk = serde_json::json!({
            "protocol": "groth16",
            "_disclaimer": "DEV ONLY - forgeable by anyone with the matching dev zkey"
        });
        let bytes = serde_json::to_vec(&vk).unwrap();
        // We can't safely flip ENV per-test without leaking into other tests,
        // so we only assert the dev-runtime branch here when the harness is
        // running in dev. The production branch is exercised by inspecting
        // the error variant when ENV is unset (default).
        let res =
            enforce_dev_vkey_policy(&bytes, std::path::Path::new("/tmp/x.vkey.json"), "Test");
        if crate::runtime_mode::is_development_runtime() {
            assert!(res.is_ok());
        } else {
            assert!(matches!(res, Err(ZkVerifyError::KeyNotFound(_))));
        }
    }

    // Path to the committed DEV verification key for ActionRangeProof. Tests
    // below are silently skipped when the file is absent (CI without the
    // snarkjs/circom toolchain). Run `bash zkp/ceremony/dev_setup.sh` to
    // produce them.
    fn dev_vkey_path(circuit: &str) -> PathBuf {
        let manifest = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest)
            .parent()
            .unwrap()
            .join("zkp/circuits/build/keys")
            .join(format!("{circuit}.dev.vkey.json"))
    }

    fn snarkjs_on_path() -> bool {
        std::process::Command::new("snarkjs")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn dev_vkey_loads_and_signals_skip_when_absent() {
        // Force dev runtime so the disclaimer path returns Ok. Using
        // SAURON_ENV (lower precedence than ENV) keeps this test from
        // colliding with `ENV=production` in CI.
        std::env::set_var("SAURON_ENV", "dev");

        let vk = dev_vkey_path("ActionRangeProof");
        if !vk.is_file() || !snarkjs_on_path() {
            eprintln!(
                "TEST SKIPPED: ZK toolchain not installed; run zkp/ceremony/dev_setup.sh first \
                 (looked at {})",
                vk.display()
            );
            return;
        }

        // Tampered proof: garbage base64 still passes structural decode but
        // snarkjs MUST reject it. We deliberately use a public_inputs vector
        // whose root matches `expected_root_hex` so we exercise the snarkjs
        // step (not just the cheap root-binding short-circuit).
        let dummy_proof = serde_json::json!({
            "pi_a": ["0", "0", "1"],
            "pi_b": [["0", "0"], ["0", "0"], ["1", "0"]],
            "pi_c": ["0", "0", "1"],
            "protocol": "groth16",
            "curve": "bn128"
        });
        use base64::Engine;
        let payload = ActionLogProofPayload {
            circuit: "ActionRangeProof".to_string(),
            public_inputs: vec!["1".into(), "0".into(), "1".into(), "100".into(), "5".into()],
            proof_b64: base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&dummy_proof).unwrap()),
            vk_id: "ActionRangeProof.dev.vk@v0".into(),
        };
        let res = verify_action_log_proof_with_vk(&payload, &"00".repeat(32), &vk).await;
        assert!(
            matches!(res, Err(ZkVerifyError::Invalid(_))),
            "expected Invalid for a hand-rolled tampered proof, got {res:?}"
        );
    }
}

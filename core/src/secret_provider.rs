//! Pluggable secret loader with envelope-encryption support.
//!
//! Resolves secrets in this priority:
//!   1. **Vault Transit** if `SAURON_VAULT_TRANSIT_ENABLED=1`. Reads the *wrapped*
//!      ciphertext from `<NAME>_WRAPPED` env, calls `POST /v1/transit/decrypt/<key>`
//!      against `SAURON_VAULT_ADDR` with token `SAURON_VAULT_TOKEN`, returns the
//!      decoded plaintext bytes. Plaintext NEVER appears in env, logs, or disk.
//!   2. **AWS KMS** if `SAURON_AWS_KMS_ENABLED=1`. Reads `<NAME>_WRAPPED` (base64
//!      KMS ciphertext) and calls `kms:Decrypt` via the AWS SDK. Plaintext NEVER
//!      persisted. (Implemented in `kms.rs` — see Phase 1B.)
//!   3. **Plain env** as the last resort: returns `<NAME>` env value verbatim.
//!
//! For local development, default is plain env. For production, set the wrapper
//! env var so the operator-managed KMS / Vault is the only place that holds the
//! plaintext root key.

use std::time::Duration;

const VAULT_DECRYPT_TIMEOUT_SECS: u64 = 5;

#[derive(Debug)]
pub enum ResolveError {
    NotFound(String),
    BackendUnavailable(String),
    Decode(String),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::NotFound(s) => write!(f, "secret not found: {s}"),
            ResolveError::BackendUnavailable(s) => write!(f, "secret backend unavailable: {s}"),
            ResolveError::Decode(s) => write!(f, "secret decode failed: {s}"),
        }
    }
}

fn flag_set(env_var: &str) -> bool {
    match std::env::var(env_var).ok() {
        Some(v) => {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        }
        None => false,
    }
}

/// Resolve a secret by NAME. Tries Vault Transit, then AWS KMS, then plain env.
pub fn resolve_secret(name: &str) -> Result<Vec<u8>, ResolveError> {
    if flag_set("SAURON_VAULT_TRANSIT_ENABLED") {
        return resolve_via_vault(name);
    }
    if flag_set("SAURON_AWS_KMS_ENABLED") {
        return resolve_via_kms(name);
    }
    resolve_via_env(name)
}

fn resolve_via_env(name: &str) -> Result<Vec<u8>, ResolveError> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Ok(v.into_bytes()),
        _ => Err(ResolveError::NotFound(name.to_string())),
    }
}

fn resolve_via_vault(name: &str) -> Result<Vec<u8>, ResolveError> {
    let addr = std::env::var("SAURON_VAULT_ADDR")
        .map_err(|_| ResolveError::BackendUnavailable("SAURON_VAULT_ADDR not set".into()))?;
    let token = std::env::var("SAURON_VAULT_TOKEN")
        .map_err(|_| ResolveError::BackendUnavailable("SAURON_VAULT_TOKEN not set".into()))?;
    let transit_key = std::env::var("SAURON_VAULT_TRANSIT_KEY")
        .map_err(|_| ResolveError::BackendUnavailable("SAURON_VAULT_TRANSIT_KEY not set".into()))?;

    let wrapped_name = format!("{name}_WRAPPED");
    let wrapped = std::env::var(&wrapped_name)
        .map_err(|_| ResolveError::NotFound(wrapped_name.clone()))?;
    if wrapped.trim().is_empty() {
        return Err(ResolveError::NotFound(wrapped_name));
    }
    if !wrapped.starts_with("vault:v") {
        return Err(ResolveError::Decode(format!(
            "{wrapped_name} does not look like Vault Transit ciphertext (expected 'vault:vN:...')"
        )));
    }

    // Synchronous HTTP via blocking reqwest: this runs only at startup, latency
    // is acceptable, and avoiding tokio::block_on simplifies the call site.
    let url = format!("{}/v1/transit/decrypt/{}", addr.trim_end_matches('/'), transit_key);
    let body = serde_json::json!({ "ciphertext": wrapped });
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(VAULT_DECRYPT_TIMEOUT_SECS))
        .build()
        .map_err(|e| ResolveError::BackendUnavailable(format!("reqwest build: {e}")))?;
    let resp = client
        .post(&url)
        .header("X-Vault-Token", token)
        .json(&body)
        .send()
        .map_err(|e| ResolveError::BackendUnavailable(format!("vault POST: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let txt = resp.text().unwrap_or_default();
        return Err(ResolveError::BackendUnavailable(format!(
            "vault decrypt {status}: {txt}"
        )));
    }
    let body: serde_json::Value = resp
        .json()
        .map_err(|e| ResolveError::Decode(format!("vault response not JSON: {e}")))?;
    let plaintext_b64 = body
        .pointer("/data/plaintext")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ResolveError::Decode("vault response missing data.plaintext".into()))?;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD
        .decode(plaintext_b64)
        .map_err(|e| ResolveError::Decode(format!("plaintext base64 decode: {e}")))
}

fn resolve_via_kms(_name: &str) -> Result<Vec<u8>, ResolveError> {
    // Phase 1B: AWS KMS code path. Stubbed here so the env flag is recognised but
    // returns an honest "not implemented" until the kms.rs adapter lands.
    Err(ResolveError::BackendUnavailable(
        "AWS KMS adapter not yet wired (Phase 1B); set SAURON_VAULT_TRANSIT_ENABLED=1 instead"
            .into(),
    ))
}

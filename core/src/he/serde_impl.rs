//! Wire formats for Paillier keys + ciphertexts.
//!
//! # NEEDS_CRYPTO_REVIEW
//!
//! This implementation has **not** been audited by a cryptographer.
//! Suitable for development and demo only. Production deployments require
//! third-party review of:
//!   (a) modular arithmetic correctness,
//!   (b) random sampling distribution,
//!   (c) message space encoding,
//!   (d) ciphertext re-randomization,
//!   (e) side-channel resistance.
//!
//! # Encoding
//!
//! - Ciphertexts: base64 (URL-safe, no padding) of the big-endian BigUint bytes.
//! - Public keys: PEM-style block `-----BEGIN PAILLIER PUBLIC KEY-----`
//!   carrying the JSON serialization of `PaillierPublicKey` (base64-wrapped).
//! - Private keys: similar but `PAILLIER PRIVATE KEY`. Never send these over
//!   the wire — server-side only.

use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use num_bigint::BigUint;

use super::paillier::{Ciphertext, HeError, PaillierPrivateKey, PaillierPublicKey};

/// Serialize a ciphertext to URL-safe base64 (no padding).
///
/// NEEDS_CRYPTO_REVIEW: format is plain base64 of the big-endian magnitude
/// bytes. NOT length-prefixed — the receiver must already know the modulus.
pub fn ciphertext_to_b64(ct: &Ciphertext) -> String {
    URL_SAFE_NO_PAD.encode(ct.c.to_bytes_be())
}

/// Parse a ciphertext from URL-safe base64 (no padding).
pub fn ciphertext_from_b64(s: &str) -> Result<Ciphertext, HeError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| HeError::InvalidParameter(format!("base64 decode failed: {e}")))?;
    if bytes.is_empty() {
        return Err(HeError::InvalidCiphertext);
    }
    let c = BigUint::from_bytes_be(&bytes);
    Ok(Ciphertext { c })
}

/// Serialize a public key as a PEM-style block carrying JSON.
///
/// NEEDS_CRYPTO_REVIEW: not RFC-7468 PEM (we don't ship DER) — just a
/// PEM-shaped envelope around the JSON serialization for human readability.
/// Wire format MUST be considered an internal interface; do not interop
/// with OpenSSL / other Paillier libraries on the basis of this header.
pub fn public_key_to_pem(pk: &PaillierPublicKey) -> Result<String, HeError> {
    let json = serde_json::to_string(pk)
        .map_err(|e| HeError::InvalidParameter(format!("json encode: {e}")))?;
    let b64 = URL_SAFE_NO_PAD.encode(json.as_bytes());
    let mut out = String::with_capacity(b64.len() + 96);
    out.push_str("-----BEGIN PAILLIER PUBLIC KEY-----\n");
    // 64-char chunks for PEM aesthetics. Not required for correctness.
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END PAILLIER PUBLIC KEY-----\n");
    Ok(out)
}

/// Parse a public key from a PEM-style block.
pub fn public_key_from_pem(s: &str) -> Result<PaillierPublicKey, HeError> {
    let body = extract_pem_body(s, "PAILLIER PUBLIC KEY")?;
    let json_bytes = URL_SAFE_NO_PAD
        .decode(body.as_bytes())
        .map_err(|e| HeError::InvalidParameter(format!("base64 decode: {e}")))?;
    serde_json::from_slice(&json_bytes)
        .map_err(|e| HeError::InvalidParameter(format!("json decode: {e}")))
}

/// Serialize a private key as a PEM-style block carrying JSON.
///
/// NEEDS_CRYPTO_REVIEW: in production this MUST be wrapped in HSM / Vault
/// envelope encryption. Never emit private keys to disk in cleartext.
pub fn private_key_to_pem(sk: &PaillierPrivateKey) -> Result<String, HeError> {
    let json = serde_json::to_string(sk)
        .map_err(|e| HeError::InvalidParameter(format!("json encode: {e}")))?;
    let b64 = URL_SAFE_NO_PAD.encode(json.as_bytes());
    let mut out = String::with_capacity(b64.len() + 96);
    out.push_str("-----BEGIN PAILLIER PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END PAILLIER PRIVATE KEY-----\n");
    Ok(out)
}

/// Parse a private key from a PEM-style block.
pub fn private_key_from_pem(s: &str) -> Result<PaillierPrivateKey, HeError> {
    let body = extract_pem_body(s, "PAILLIER PRIVATE KEY")?;
    let json_bytes = URL_SAFE_NO_PAD
        .decode(body.as_bytes())
        .map_err(|e| HeError::InvalidParameter(format!("base64 decode: {e}")))?;
    serde_json::from_slice(&json_bytes)
        .map_err(|e| HeError::InvalidParameter(format!("json decode: {e}")))
}

fn extract_pem_body(s: &str, label: &str) -> Result<String, HeError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = s
        .find(&begin)
        .ok_or_else(|| HeError::InvalidParameter(format!("missing {begin}")))?;
    let after_begin = start + begin.len();
    let stop = s[after_begin..]
        .find(&end)
        .ok_or_else(|| HeError::InvalidParameter(format!("missing {end}")))?;
    let body: String = s[after_begin..after_begin + stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::he::paillier::PaillierPrivateKey;
    use num_bigint::BigUint;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn small_keypair() -> PaillierPrivateKey {
        let p = BigUint::from(17u32);
        let q = BigUint::from(19u32);
        PaillierPrivateKey::from_primes(&p, &q).unwrap()
    }

    #[test]
    fn test_ciphertext_b64_roundtrip() {
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(11);
        let m = BigUint::from(42u32);
        let ct = sk.public.encrypt(&m, &mut rng).unwrap();
        let s = ciphertext_to_b64(&ct);
        let ct2 = ciphertext_from_b64(&s).unwrap();
        assert_eq!(ct, ct2);
        assert_eq!(sk.decrypt(&ct2).unwrap(), m);
    }

    #[test]
    fn test_public_key_pem_roundtrip() {
        let sk = small_keypair();
        let pem = public_key_to_pem(&sk.public).unwrap();
        assert!(pem.contains("-----BEGIN PAILLIER PUBLIC KEY-----"));
        let pk2 = public_key_from_pem(&pem).unwrap();
        assert_eq!(sk.public, pk2);
    }

    #[test]
    fn test_private_key_pem_roundtrip() {
        let sk = small_keypair();
        let pem = private_key_to_pem(&sk).unwrap();
        assert!(pem.contains("-----BEGIN PAILLIER PRIVATE KEY-----"));
        let sk2 = private_key_from_pem(&pem).unwrap();
        assert_eq!(sk, sk2);
    }

    #[test]
    fn test_b64_decode_rejects_empty() {
        let r = ciphertext_from_b64("");
        assert!(matches!(r, Err(HeError::InvalidCiphertext)));
    }

    #[test]
    fn test_pem_extraction_missing_header_errors() {
        let r = public_key_from_pem("no header here");
        assert!(r.is_err());
    }
}

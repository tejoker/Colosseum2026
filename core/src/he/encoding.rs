//! Fixed-point ↔ Paillier message space encoding.
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
//! # Signed encoding (`ZpZn`-style)
//!
//! Paillier's plaintext space Z_n contains only non-negative integers in
//! [0, n). To represent signed values, we split the message space at n/2:
//!   - values in [0, n/2)         → positive
//!   - values in [n/2, n)         → negative (decoded as `m - n`)
//!
//! Encoded as fixed-point with a caller-supplied `scale` (e.g. `1000` for
//! 3 decimal places).
//!
//! NEEDS_CRYPTO_REVIEW: overflow handling in `encode_f64` clamps silently
//! at the modulus boundary. Callers MUST validate magnitudes against the
//! modulus before encoding for safety-critical applications.

use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};

use super::paillier::HeError;

/// Encode a signed `f64` as a Paillier-message-space `BigUint` using
/// fixed-point scaling. NOT keyed to any modulus — caller is responsible for
/// ensuring the encoded value is in [0, n).
///
/// Examples (scale = 1000):
///   - encode_f64(1.5)   → 1500
///   - encode_f64(-1.5)  → encoded as "n - 1500" (returned as `BigUint::from(1500)` —
///                         the negation against a modulus happens in
///                         [`encode_f64_for_modulus`] below).
///
/// NEEDS_CRYPTO_REVIEW: this raw form does not know n. Use
/// [`encode_f64_for_modulus`] when you have one — that's the safe path.
pub fn encode_f64(v: f64, scale: u32) -> BigUint {
    let scale_f = scale as f64;
    let scaled = (v * scale_f).round();
    if scaled < 0.0 {
        // Caller has no modulus context here — return the magnitude.
        BigUint::from(scaled.abs() as u64)
    } else {
        BigUint::from(scaled as u64)
    }
}

/// Modulus-aware signed encoder. Negative values map to `n - |v|` so that
/// values in [n/2, n) decode as negative.
///
/// NEEDS_CRYPTO_REVIEW: signed encoding splits the message space — payloads
/// must stay below n/2 in magnitude or wrap silently.
pub fn encode_f64_for_modulus(v: f64, scale: u32, n: &BigUint) -> Result<BigUint, HeError> {
    if !v.is_finite() {
        return Err(HeError::InvalidParameter("non-finite f64".into()));
    }
    let scale_f = scale as f64;
    let scaled = (v * scale_f).round();
    // Guard against the half-modulus magnitude budget.
    let half = n >> 1;
    let mag_f = scaled.abs();
    if mag_f >= u64::MAX as f64 {
        return Err(HeError::DecodeOverflow);
    }
    let mag = BigUint::from(mag_f as u64);
    if mag >= half {
        return Err(HeError::DecodeOverflow);
    }
    if scaled < 0.0 {
        Ok(n - mag)
    } else {
        Ok(mag)
    }
}

/// Decode a Paillier-message-space `BigUint` back to `f64`. Reverses
/// [`encode_f64`] for unsigned values only. For signed decoding use
/// [`decode_f64_signed`].
pub fn decode_f64(m: &BigUint, scale: u32) -> Result<f64, HeError> {
    let raw = m
        .to_u64()
        .ok_or(HeError::DecodeOverflow)?;
    Ok((raw as f64) / (scale as f64))
}

/// Signed decoder. Values >= n/2 decode as negative.
///
/// NEEDS_CRYPTO_REVIEW: the >= n/2 cutoff matches the encoder. The half
/// boundary is **exclusive on the positive side** and inclusive on the
/// negative side — confirm this matches the application's sign convention.
pub fn decode_f64_signed(m: &BigUint, scale: u32, n: &BigUint) -> Result<f64, HeError> {
    if m >= n {
        return Err(HeError::DecodeOverflow);
    }
    let half = n >> 1;
    if m >= &half {
        // Negative branch: real value = m - n  (as signed integer).
        let mag_big = n - m;
        let mag = mag_big.to_u64().ok_or(HeError::DecodeOverflow)?;
        Ok(-((mag as f64) / (scale as f64)))
    } else if m.is_zero() {
        Ok(0.0)
    } else {
        let mag = m.to_u64().ok_or(HeError::DecodeOverflow)?;
        Ok((mag as f64) / (scale as f64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_zero_roundtrips() {
        let m = encode_f64(0.0, 1000);
        assert_eq!(m, BigUint::from(0u32));
        let v = decode_f64(&m, 1000).unwrap();
        assert!((v - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_encode_one_point_five() {
        let m = encode_f64(1.5, 1000);
        assert_eq!(m, BigUint::from(1500u32));
        let v = decode_f64(&m, 1000).unwrap();
        assert!((v - 1.5).abs() < 1e-9);
    }

    #[test]
    fn test_encode_large_value_unsigned() {
        let m = encode_f64(987654.321, 1000);
        assert_eq!(m, BigUint::from(987_654_321u64));
        let v = decode_f64(&m, 1000).unwrap();
        assert!((v - 987654.321).abs() < 1e-6);
    }

    #[test]
    fn test_signed_negative_roundtrips_with_modulus() {
        let n = BigUint::from(1_000_000u32);
        // -1.5 with scale 1000 → 1500 negative → n - 1500 = 998500
        let m = encode_f64_for_modulus(-1.5, 1000, &n).unwrap();
        assert_eq!(m, BigUint::from(998_500u32));
        let v = decode_f64_signed(&m, 1000, &n).unwrap();
        assert!((v - (-1.5)).abs() < 1e-9, "got {v}");
    }

    #[test]
    fn test_signed_positive_roundtrips_with_modulus() {
        let n = BigUint::from(1_000_000u32);
        let m = encode_f64_for_modulus(123.456, 1000, &n).unwrap();
        assert_eq!(m, BigUint::from(123_456u32));
        let v = decode_f64_signed(&m, 1000, &n).unwrap();
        assert!((v - 123.456).abs() < 1e-6);
    }

    #[test]
    fn test_signed_encoder_rejects_magnitude_above_half_modulus() {
        // n = 1_000_000, half = 500_000. 600.0 * 1000 = 600_000 > half → reject.
        let n = BigUint::from(1_000_000u32);
        let r = encode_f64_for_modulus(600.0, 1000, &n);
        assert!(matches!(r, Err(HeError::DecodeOverflow)));
    }

    #[test]
    fn test_signed_encoder_rejects_non_finite() {
        let n = BigUint::from(1_000_000u32);
        assert!(encode_f64_for_modulus(f64::NAN, 1000, &n).is_err());
        assert!(encode_f64_for_modulus(f64::INFINITY, 1000, &n).is_err());
    }

    #[test]
    fn test_decode_overflow_when_m_too_big_for_u64() {
        // Build a BigUint > u64::MAX so to_u64 returns None.
        let m = BigUint::from(u64::MAX) * BigUint::from(2u32);
        let r = decode_f64(&m, 1000);
        assert!(matches!(r, Err(HeError::DecodeOverflow)));
    }

    #[test]
    fn test_signed_decode_zero_branch() {
        let n = BigUint::from(1_000_000u32);
        let m = BigUint::from(0u32);
        let v = decode_f64_signed(&m, 1000, &n).unwrap();
        assert_eq!(v, 0.0);
    }
}

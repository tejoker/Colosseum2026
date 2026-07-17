//! Homomorphic aggregator (Sprint 13-14, Tier 2).
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
//! # Wire flow (secret-sum use case)
//!
//! ```text
//!   Customer X (SDK)                 Server                       Operator
//!   ────────────────                 ──────                       ────────
//!   encrypt v_X with pk_cohort ───►  POST /v1/stats/submit-encrypted
//!                                    │
//!                                    ├─ load aggregator row
//!                                    ├─ homomorphic add into running sum
//!                                    ├─ persist new b64 ciphertext
//!                                    └─ return aggregation_id
//!
//!                                    Operator-only finalize step:
//!                                       sk = load-from-vault(pk_id)
//!                                       aggregate = HeAggregator.finalize(sk)
//!                                       publish DP-noised aggregate
//! ```
//!
//! The server **never** decrypts an individual customer's ciphertext.
//! Only the cohort-level aggregate is decrypted, and only by an operator
//! who has access to the cohort private key.

use num_integer::Integer;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};

use crate::he::paillier::{Ciphertext, HeError, PaillierPrivateKey, PaillierPublicKey};

/// In-memory homomorphic accumulator. One per `(cohort, metric, period)`.
///
/// NEEDS_CRYPTO_REVIEW: this type is the cryptographic counterpart of the
/// plaintext `customer_stats` table. Its invariants — monotone contribution
/// counter, key-bound public key id, ciphertext membership in Z_{n^2}* —
/// should be checked at every persistence boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeAggregator {
    /// Public key the running sum is encrypted under.
    pub pk: PaillierPublicKey,
    /// Running ciphertext encoding the homomorphic sum.
    pub sum_ciphertext: Ciphertext,
    /// Number of customer contributions so far.
    pub n_contributions: u32,
}

impl HeAggregator {
    /// Initialise an aggregator with a fresh Enc(0) under the given key.
    ///
    /// # RNG requirement
    ///
    /// **Production callers MUST pass a CSPRNG** (e.g. `rand::rngs::OsRng`)
    /// since the initial Enc(0) is the seed of the running sum.
    ///
    /// NEEDS_CRYPTO_REVIEW: the initial ciphertext IS fresh randomness, so
    /// nothing about the cohort leaks through the seed value alone.
    pub fn new<R: rand::RngCore>(pk: PaillierPublicKey, rng: &mut R) -> Result<Self, HeError> {
        let zero = pk.encrypt_zero(rng)?;
        Ok(Self {
            pk,
            sum_ciphertext: zero,
            n_contributions: 0,
        })
    }

    /// Restore an aggregator from persisted state.
    pub fn from_parts(
        pk: PaillierPublicKey,
        sum_ciphertext: Ciphertext,
        n_contributions: u32,
    ) -> Self {
        Self {
            pk,
            sum_ciphertext,
            n_contributions,
        }
    }

    /// Homomorphically add a customer ciphertext into the running sum.
    /// Does not require the private key. Increments the contribution counter.
    ///
    /// Membership check: rejects `c = 0`, `c ≥ n²`, and `gcd(c, n) ≠ 1`. The
    /// last test is the cryptographic-review F-3 hardening: a ciphertext
    /// whose value shares a factor with `n` would (a) leak the factorisation
    /// of `n` to anyone who can run a successful gcd against it and
    /// (b) decrypt to undefined garbage. A correctly-encrypted Paillier
    /// ciphertext is `(1 + m·n) · r^n mod n²` with `r ∈ Z_n*`, which
    /// satisfies `gcd(c, n) = 1` by construction; honest clients never
    /// trip this check.
    ///
    /// What this check does **not** defend against: a malicious client
    /// submitting `Enc(huge value)` to bias the aggregate. That requires a
    /// protocol-layer range proof on the submitted plaintext (see
    /// `docs/crypto-review-attestation.md` F-3). The gcd check is a strict
    /// improvement but **not** the soundness-correct path on its own.
    pub fn add_encrypted(&mut self, ct: &Ciphertext) -> Result<(), HeError> {
        if ct.c.is_zero() || ct.c >= self.pk.n_squared {
            return Err(HeError::InvalidCiphertext);
        }
        // F-3 hardening: reject ciphertexts that share a factor with n. We
        // gcd against n (not n²) — gcd(c, n²) collapses to gcd(c, n) for
        // semiprime n = p·q, and gcd against n is half the work.
        if !ct.c.gcd(&self.pk.n).is_one() {
            return Err(HeError::InvalidCiphertext);
        }
        self.sum_ciphertext = self.pk.add(&self.sum_ciphertext, ct);
        self.n_contributions = self.n_contributions.saturating_add(1);
        Ok(())
    }

    /// Decrypt the aggregate. Consumes self — finalisation is one-shot.
    ///
    /// NEEDS_CRYPTO_REVIEW: returns the raw decrypted value clamped into
    /// a `u64`. If the true aggregate exceeds u64::MAX, callers receive
    /// only the low-order 64 bits. For cohorts likely to exceed this
    /// bound, decode against the full BigUint.
    pub fn finalize(self, sk: &PaillierPrivateKey) -> Result<u64, HeError> {
        let m = sk.decrypt(&self.sum_ciphertext)?;
        Ok(u64_from_biguint_lossy(&m))
    }

    /// Decrypt and return the full plaintext BigUint without truncation.
    /// Use this if your aggregate may exceed u64.
    pub fn finalize_biguint(self, sk: &PaillierPrivateKey) -> Result<num_bigint::BigUint, HeError> {
        sk.decrypt(&self.sum_ciphertext)
    }
}

fn u64_from_biguint_lossy(b: &num_bigint::BigUint) -> u64 {
    use num_traits::ToPrimitive;
    b.to_u64().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::he::paillier::PaillierPrivateKey;
    use num_bigint::BigUint;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn small_keypair() -> PaillierPrivateKey {
        // n = 17 * 19 = 323. Plenty for sums under ~150.
        PaillierPrivateKey::from_primes(&BigUint::from(17u32), &BigUint::from(19u32)).unwrap()
    }

    #[test]
    fn test_aggregator_sums_three_contributions() {
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(20);
        let mut agg = HeAggregator::new(sk.public.clone(), &mut rng).unwrap();
        for v in [10u32, 20, 30] {
            let ct = sk.public.encrypt(&BigUint::from(v), &mut rng).unwrap();
            agg.add_encrypted(&ct).unwrap();
        }
        assert_eq!(agg.n_contributions, 3);
        let total = agg.finalize(&sk).unwrap();
        assert_eq!(total, 60);
    }

    #[test]
    fn test_aggregator_rejects_zero_ciphertext() {
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(21);
        let mut agg = HeAggregator::new(sk.public.clone(), &mut rng).unwrap();
        let bad = Ciphertext {
            c: BigUint::from(0u32),
        };
        assert!(matches!(
            agg.add_encrypted(&bad),
            Err(HeError::InvalidCiphertext)
        ));
        assert_eq!(agg.n_contributions, 0);
    }

    #[test]
    fn test_aggregator_empty_sum_decrypts_to_zero() {
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(22);
        let agg = HeAggregator::new(sk.public.clone(), &mut rng).unwrap();
        assert_eq!(agg.finalize(&sk).unwrap(), 0);
    }

    #[test]
    fn test_aggregator_rejects_ciphertext_sharing_factor_with_n() {
        // F-3 hardening: n = 17*19 = 323. A ciphertext c = 17 shares the
        // factor 17 with n, so gcd(c, n) = 17 ≠ 1 → reject.
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(23);
        let mut agg = HeAggregator::new(sk.public.clone(), &mut rng).unwrap();
        let bad_p = Ciphertext {
            c: BigUint::from(17u32),
        };
        let bad_q = Ciphertext {
            c: BigUint::from(19u32),
        };
        let bad_pq = Ciphertext {
            c: BigUint::from(17u32 * 19),
        };
        assert!(matches!(
            agg.add_encrypted(&bad_p),
            Err(HeError::InvalidCiphertext)
        ));
        assert!(matches!(
            agg.add_encrypted(&bad_q),
            Err(HeError::InvalidCiphertext)
        ));
        assert!(matches!(
            agg.add_encrypted(&bad_pq),
            Err(HeError::InvalidCiphertext)
        ));
        assert_eq!(agg.n_contributions, 0);
    }
}

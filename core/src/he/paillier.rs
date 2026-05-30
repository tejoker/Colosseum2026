//! Paillier cryptosystem core (Tier 2, Sprint 13-14).
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
//! # References
//!
//! - Paillier, "Public-Key Cryptosystems Based on Composite Degree
//!   Residuosity Classes", EUROCRYPT 1999.
//! - HAC 4.2.3 (Miller-Rabin probabilistic primality test).
//!
//! # Algorithm (textbook Paillier with g = n + 1 optimisation)
//!
//! Key generation:
//!   1. Sample two equal-length primes p, q with `bits/2` bits each.
//!   2. n = p * q,  n^2 = n * n.
//!   3. lambda = lcm(p - 1, q - 1).
//!   4. g = n + 1 (textbook simplification — L(g^lambda mod n^2) = lambda).
//!   5. mu = lambda^{-1} mod n.
//!
//! Encryption of m ∈ [0, n):
//!   1. Sample r ∈ Z_n* (gcd(r, n) = 1).
//!   2. c = (1 + m*n) * r^n  mod n^2.
//!
//! Decryption of c ∈ Z_{n^2}*:
//!   1. u = c^lambda  mod n^2.
//!   2. L(u) = (u - 1) / n   (integer division — exact by construction).
//!   3. m = L(u) * mu  mod n.
//!
//! Homomorphic add:  c1 * c2  mod n^2  decrypts to  m1 + m2  mod n.
//! Scalar mul:       c^k       mod n^2  decrypts to  m * k    mod n.
//! Re-randomize:     c * s^n   mod n^2  for fresh s ∈ Z_n*.

use std::fmt;

use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Number of Miller-Rabin rounds used during prime generation. 40 rounds
/// gives a false-positive probability of 4^-40 ≈ 8.27e-25, which is the
/// industry-standard depth for RSA/Paillier key generation.
///
/// NEEDS_CRYPTO_REVIEW: rounds count + witness sampling distribution
/// should be confirmed by a cryptographer before production deployment.
pub const MILLER_RABIN_ROUNDS: u32 = 40;

/// Errors produced by the HE module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeError {
    /// Plaintext is outside [0, n).
    MessageOutOfRange,
    /// Ciphertext is not in Z_{n^2}* (zero, or shares a factor with n^2).
    InvalidCiphertext,
    /// Random sampling exhausted retry budget (extremely improbable).
    RandomSamplingFailed,
    /// Decoding a BigUint back to f64 overflowed or lost precision past the
    /// representable range.
    DecodeOverflow,
    /// Generic invalid parameter (e.g. bits < 64).
    InvalidParameter(String),
}

impl fmt::Display for HeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeError::MessageOutOfRange => write!(f, "message must be in [0, n)"),
            HeError::InvalidCiphertext => write!(f, "ciphertext not in Z_{{n^2}}*"),
            HeError::RandomSamplingFailed => write!(f, "rejection sampling exhausted retries"),
            HeError::DecodeOverflow => write!(f, "decode out of representable range"),
            HeError::InvalidParameter(m) => write!(f, "invalid parameter: {m}"),
        }
    }
}

impl std::error::Error for HeError {}

/// Paillier public key.
///
/// NEEDS_CRYPTO_REVIEW: serialized form must be authenticated when
/// transmitted (e.g. wrapped in a server-signed envelope) — the public
/// key alone is **not** an integrity anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaillierPublicKey {
    /// RSA-style modulus n = p * q.
    pub n: BigUint,
    /// Precomputed n^2 (used in every encrypt + decrypt).
    pub n_squared: BigUint,
    /// Generator. With the n + 1 simplification, `g = n + 1` always.
    pub g: BigUint,
}

/// Paillier private key.
///
/// NEEDS_CRYPTO_REVIEW: prime factors p, q are **discarded** after key
/// generation. Production deployments may want to retain them (under HSM
/// custody) for CRT-accelerated decryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaillierPrivateKey {
    /// Matching public key.
    pub public: PaillierPublicKey,
    /// Carmichael totient lambda = lcm(p-1, q-1).
    pub lambda: BigUint,
    /// Decryption helper mu = lambda^{-1} mod n.
    pub mu: BigUint,
}

/// Paillier ciphertext. Lives in Z_{n^2}*.
///
/// NEEDS_CRYPTO_REVIEW: ciphertexts are **malleable** by design — that
/// is the homomorphism. Applications that need ciphertext integrity
/// must wrap them in an authenticated envelope (e.g. signed by the
/// submitting client) at the protocol layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ciphertext {
    /// Raw ciphertext value c ∈ Z_{n^2}*.
    pub c: BigUint,
}

impl PaillierPublicKey {
    /// Encrypt a message m ∈ [0, n).
    ///
    /// # RNG requirement
    ///
    /// **Production callers MUST pass a CSPRNG** (e.g. `rand::rngs::OsRng`).
    /// `r` becomes part of the ciphertext; predictable `r` makes the
    /// scheme deterministic and breaks IND-CPA.
    ///
    /// NEEDS_CRYPTO_REVIEW: r is sampled uniformly from Z_n* via rejection
    /// sampling. Not constant-time. Side-channel resistance is out of scope.
    pub fn encrypt(
        &self,
        m: &BigUint,
        rng: &mut impl RngCore,
    ) -> Result<Ciphertext, HeError> {
        if m >= &self.n {
            return Err(HeError::MessageOutOfRange);
        }
        let r = sample_zn_star(&self.n, rng)?;
        // c = (1 + m*n) * r^n   mod n^2
        // Uses the g = n+1 simplification: (n+1)^m = 1 + m*n   mod n^2
        // (true by the binomial expansion — every higher-order term has n^2).
        let one_plus_mn: BigUint = (BigUint::one() + m * &self.n) % &self.n_squared;
        let r_to_n = r.modpow(&self.n, &self.n_squared);
        let c = (one_plus_mn * r_to_n) % &self.n_squared;
        Ok(Ciphertext { c })
    }

    /// Homomorphic addition: Enc(a) ⊕ Enc(b) = Enc(a + b mod n).
    ///
    /// Implementation: c3 = c1 * c2 mod n^2. No randomness consumed.
    ///
    /// NEEDS_CRYPTO_REVIEW: the result ciphertext is **not** re-randomized
    /// by default. Callers that publish intermediate sums should call
    /// [`PaillierPublicKey::rerandomize`] to hide which addends produced it.
    pub fn add(&self, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        let c = (&a.c * &b.c) % &self.n_squared;
        Ciphertext { c }
    }

    /// Scalar multiplication: Enc(a) ⊗ k = Enc(a * k mod n).
    ///
    /// Implementation: c2 = c^k mod n^2.
    ///
    /// NEEDS_CRYPTO_REVIEW: not re-randomized. See note on `add`.
    pub fn mul_scalar(&self, a: &Ciphertext, k: &BigUint) -> Ciphertext {
        let c = a.c.modpow(k, &self.n_squared);
        Ciphertext { c }
    }

    /// Re-randomize: produce a fresh-looking ciphertext that decrypts to the
    /// same plaintext. Adds zero homomorphically by multiplying by Enc(0)
    /// with new randomness.
    ///
    /// # RNG requirement
    ///
    /// **Production callers MUST pass a CSPRNG** (e.g. `rand::rngs::OsRng`).
    /// Predictable randomness defeats unlinkability — the whole point of
    /// re-randomisation is that a third party cannot tell two ciphertexts
    /// of the same plaintext apart.
    ///
    /// NEEDS_CRYPTO_REVIEW: rejection sampling over r, not constant-time.
    pub fn rerandomize(
        &self,
        ct: &Ciphertext,
        rng: &mut impl RngCore,
    ) -> Result<Ciphertext, HeError> {
        let r = sample_zn_star(&self.n, rng)?;
        let r_to_n = r.modpow(&self.n, &self.n_squared);
        let c = (&ct.c * r_to_n) % &self.n_squared;
        Ok(Ciphertext { c })
    }

    /// Return a fresh ciphertext encrypting 0. Useful for initialising a
    /// homomorphic accumulator. Re-randomized on each call.
    ///
    /// NEEDS_CRYPTO_REVIEW: rejection sampling. See note on `encrypt`.
    pub fn encrypt_zero(&self, rng: &mut impl RngCore) -> Result<Ciphertext, HeError> {
        self.encrypt(&BigUint::zero(), rng)
    }
}

impl PaillierPrivateKey {
    /// Generate a fresh keypair with the requested modulus bit length.
    ///
    /// # RNG requirement
    ///
    /// **Production callers MUST pass a CSPRNG** (e.g. `rand::rngs::OsRng`).
    /// A predictable RNG here exposes the private key directly — every
    /// candidate prime is derivable from the seed.
    ///
    /// NEEDS_CRYPTO_REVIEW: prime generation uses Miller-Rabin with
    /// [`MILLER_RABIN_ROUNDS`] rounds (default 40). Witness distribution
    /// + sampling correctness should be verified by a cryptographer
    /// before production use. Default bit length is 2048.
    pub fn generate(bits: usize, rng: &mut impl RngCore) -> Result<Self, HeError> {
        if bits < 64 {
            return Err(HeError::InvalidParameter(
                "bits must be >= 64".to_string(),
            ));
        }
        if bits % 2 != 0 {
            return Err(HeError::InvalidParameter("bits must be even".to_string()));
        }
        let half = bits / 2;
        // Sample two distinct primes of half-modulus length. Ensures
        // p * q has approximately `bits` bits (top bit forced via the
        // gen_prime helper).
        let p = gen_prime(half, rng);
        let mut q = gen_prime(half, rng);
        while q == p {
            q = gen_prime(half, rng);
        }
        Self::from_primes(&p, &q)
    }

    /// Assemble a keypair from explicit primes. Used by tests + key import.
    ///
    /// NEEDS_CRYPTO_REVIEW: primality of p and q is **not** rechecked.
    /// Callers passing externally-supplied primes (e.g. from PEM) must
    /// verify primality themselves.
    pub fn from_primes(p: &BigUint, q: &BigUint) -> Result<Self, HeError> {
        if p == q {
            return Err(HeError::InvalidParameter("p must differ from q".into()));
        }
        let n = p * q;
        let n_squared = &n * &n;
        let g = &n + BigUint::one();
        let p_minus_1 = p - 1u32;
        let q_minus_1 = q - 1u32;
        let lambda = p_minus_1.lcm(&q_minus_1);
        // With g = n+1, L(g^lambda mod n^2) = lambda  mod n,
        // so mu = lambda^{-1} mod n. Use the extended GCD.
        let mu = mod_inv(&lambda, &n).ok_or_else(|| {
            HeError::InvalidParameter("lambda not invertible mod n".into())
        })?;
        Ok(Self {
            public: PaillierPublicKey { n, n_squared, g },
            lambda,
            mu,
        })
    }

    /// Decrypt a ciphertext to a BigUint in [0, n).
    ///
    /// NEEDS_CRYPTO_REVIEW: not constant-time. Modular exponentiation in
    /// `num-bigint` can leak timing information about lambda; production
    /// systems should use a constant-time bigint backend.
    pub fn decrypt(&self, ct: &Ciphertext) -> Result<BigUint, HeError> {
        let n = &self.public.n;
        let n_squared = &self.public.n_squared;
        if ct.c.is_zero() || &ct.c >= n_squared {
            return Err(HeError::InvalidCiphertext);
        }
        // u = c^lambda mod n^2
        let u = ct.c.modpow(&self.lambda, n_squared);
        // L(u) = (u - 1) / n. Exact integer division by construction: u ≡ 1 mod n.
        let u_minus_1 = u - 1u32;
        let l_u = &u_minus_1 / n;
        // m = L(u) * mu mod n
        let m = (l_u * &self.mu) % n;
        Ok(m)
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────

/// Uniform sampler over Z_n* via rejection sampling.
///
/// NEEDS_CRYPTO_REVIEW: rejection sampling rejects values with `gcd(r, n) != 1`.
/// For 2048-bit n with the standard factor distribution, the rejection rate
/// is overwhelmingly small (≈ 1/p + 1/q), so 256 retries always succeeds in
/// practice. Distribution + the gcd check should be cryptographer-reviewed.
fn sample_zn_star(n: &BigUint, rng: &mut impl RngCore) -> Result<BigUint, HeError> {
    let bits = n.bits();
    for _ in 0..256 {
        let r = rng.gen_biguint(bits);
        if r >= BigUint::one() && &r < n && r.gcd(n).is_one() {
            return Ok(r);
        }
    }
    Err(HeError::RandomSamplingFailed)
}

/// Extended Euclidean modular inverse. Returns None if a is not invertible.
fn mod_inv(a: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;
    use num_bigint::Sign;
    let a_i = BigInt::from_biguint(Sign::Plus, a.clone());
    let m_i = BigInt::from_biguint(Sign::Plus, modulus.clone());
    let egcd = a_i.extended_gcd(&m_i);
    if !egcd.gcd.is_one() {
        return None;
    }
    let mut x = egcd.x;
    // Reduce x into [0, m).
    x %= &m_i;
    if x.sign() == Sign::Minus {
        x += &m_i;
    }
    let (_, mag) = x.into_parts();
    Some(mag)
}

/// Generate a probable prime with the requested bit length. Top + bottom bits
/// forced (top for length, bottom for oddness). Miller-Rabin checked.
///
/// NEEDS_CRYPTO_REVIEW: candidate generation forces bits 0 and `bits-1` to 1.
/// This matches OpenSSL's RSA prime generation but should be reviewed for
/// any distributional biases relevant to Paillier specifically.
fn gen_prime(bits: usize, rng: &mut impl RngCore) -> BigUint {
    loop {
        let mut candidate = rng.gen_biguint(bits as u64);
        // Set top bit (ensures bit length) and bottom bit (ensures odd).
        candidate.set_bit((bits - 1) as u64, true);
        candidate.set_bit(0, true);
        if is_probable_prime(&candidate, MILLER_RABIN_ROUNDS, rng) {
            return candidate;
        }
    }
}

/// Small-prime trial division then Miller-Rabin. Returns true if n is
/// probably prime. False-positive probability ≤ 4^{-rounds}.
fn is_probable_prime(n: &BigUint, rounds: u32, rng: &mut impl RngCore) -> bool {
    if *n < BigUint::from(2u32) {
        return false;
    }
    if *n == BigUint::from(2u32) || *n == BigUint::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }
    // Trial divide by small primes up to 1000 to short-circuit obvious composites.
    const SMALL_PRIMES: &[u32] = &[
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
        191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
        283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
        401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
        509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619,
        631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743,
        751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
        877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
    ];
    for &p in SMALL_PRIMES {
        let p_big = BigUint::from(p);
        if n == &p_big {
            return true;
        }
        if (n % &p_big).is_zero() {
            return false;
        }
    }
    miller_rabin(n, rounds, rng)
}

/// Miller-Rabin probabilistic primality test with `rounds` random witnesses.
///
/// NEEDS_CRYPTO_REVIEW: witness sampling is rejection-sampled in [2, n-2].
/// 40 rounds gives ≤ 4^-40 false-positive probability — industry standard.
fn miller_rabin(n: &BigUint, rounds: u32, rng: &mut impl RngCore) -> bool {
    // Write n-1 = 2^s * d with d odd.
    let n_minus_1 = n - 1u32;
    let mut d = n_minus_1.clone();
    let mut s = 0u32;
    while d.is_even() {
        d >>= 1;
        s += 1;
    }
    let n_minus_2 = n - 2u32;
    let bits = n.bits();
    'outer: for _ in 0..rounds {
        // Sample a in [2, n-2].
        let a = loop {
            let candidate = rng.gen_biguint(bits);
            if candidate >= BigUint::from(2u32) && candidate <= n_minus_2 {
                break candidate;
            }
        };
        let mut x = a.modpow(&d, n);
        if x.is_one() || x == n_minus_1 {
            continue;
        }
        for _ in 0..(s - 1) {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n_minus_1 {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

// ─── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Fast test keypair (small primes — NOT secure, just exercises the algebra).
    fn small_keypair() -> PaillierPrivateKey {
        // p = 17, q = 19 → n = 323. Plaintext space Z_323.
        let p = BigUint::from(17u32);
        let q = BigUint::from(19u32);
        PaillierPrivateKey::from_primes(&p, &q).unwrap()
    }

    /// 512-bit keypair — bigger but still fast (<1s typical) for the full
    /// encrypt/decrypt round trip.
    fn medium_keypair(seed: u64) -> PaillierPrivateKey {
        let mut rng = StdRng::seed_from_u64(seed);
        PaillierPrivateKey::generate(512, &mut rng).unwrap()
    }

    #[test]
    fn test_encrypt_zero_decrypts_to_zero() {
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(1);
        let m = BigUint::zero();
        let ct = sk.public.encrypt(&m, &mut rng).unwrap();
        let pt = sk.decrypt(&ct).unwrap();
        assert_eq!(pt, m);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_many_values() {
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(2);
        for m_val in [0u32, 1, 2, 42, 100, 200, 322] {
            let m = BigUint::from(m_val);
            let ct = sk.public.encrypt(&m, &mut rng).unwrap();
            let pt = sk.decrypt(&ct).unwrap();
            assert_eq!(pt, m, "roundtrip failed at m={m_val}");
        }
    }

    #[test]
    fn test_homomorphic_add_decrypts_to_sum_mod_n() {
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(3);
        let a = BigUint::from(30u32);
        let b = BigUint::from(50u32);
        let ca = sk.public.encrypt(&a, &mut rng).unwrap();
        let cb = sk.public.encrypt(&b, &mut rng).unwrap();
        let csum = sk.public.add(&ca, &cb);
        let pt = sk.decrypt(&csum).unwrap();
        assert_eq!(pt, BigUint::from(80u32));
    }

    #[test]
    fn test_homomorphic_add_wraps_mod_n() {
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(4);
        // n = 323. 200 + 200 = 400 ≡ 77 mod 323.
        let a = BigUint::from(200u32);
        let b = BigUint::from(200u32);
        let ca = sk.public.encrypt(&a, &mut rng).unwrap();
        let cb = sk.public.encrypt(&b, &mut rng).unwrap();
        let csum = sk.public.add(&ca, &cb);
        let pt = sk.decrypt(&csum).unwrap();
        assert_eq!(pt, BigUint::from(77u32));
    }

    #[test]
    fn test_mul_scalar_decrypts_to_product_mod_n() {
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(5);
        let a = BigUint::from(7u32);
        let k = BigUint::from(11u32);
        let ca = sk.public.encrypt(&a, &mut rng).unwrap();
        let cprod = sk.public.mul_scalar(&ca, &k);
        let pt = sk.decrypt(&cprod).unwrap();
        assert_eq!(pt, BigUint::from(77u32));
    }

    #[test]
    fn test_rerandomize_preserves_plaintext() {
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(6);
        let m = BigUint::from(123u32);
        let ct = sk.public.encrypt(&m, &mut rng).unwrap();
        let ct2 = sk.public.rerandomize(&ct, &mut rng).unwrap();
        assert_ne!(ct.c, ct2.c, "rerandomize must change the ciphertext");
        assert_eq!(sk.decrypt(&ct2).unwrap(), m);
    }

    #[test]
    fn test_encrypt_twice_gives_different_ciphertexts() {
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(7);
        let m = BigUint::from(42u32);
        let c1 = sk.public.encrypt(&m, &mut rng).unwrap();
        let c2 = sk.public.encrypt(&m, &mut rng).unwrap();
        assert_ne!(c1.c, c2.c, "fresh r must produce a different ciphertext");
        assert_eq!(sk.decrypt(&c1).unwrap(), sk.decrypt(&c2).unwrap());
    }

    #[test]
    fn test_encrypt_boundary_zero_one_n_minus_one() {
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(8);
        let n_minus_1 = &sk.public.n - 1u32;
        for m in [BigUint::zero(), BigUint::one(), n_minus_1.clone()] {
            let ct = sk.public.encrypt(&m, &mut rng).unwrap();
            assert_eq!(sk.decrypt(&ct).unwrap(), m);
        }
    }

    #[test]
    fn test_encrypt_rejects_message_equal_or_above_n() {
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(9);
        let n = sk.public.n.clone();
        let r1 = sk.public.encrypt(&n, &mut rng);
        assert!(matches!(r1, Err(HeError::MessageOutOfRange)));
        let r2 = sk.public.encrypt(&(&n + 1u32), &mut rng);
        assert!(matches!(r2, Err(HeError::MessageOutOfRange)));
    }

    #[test]
    fn test_decrypt_rejects_zero_ciphertext() {
        let sk = small_keypair();
        let bad = Ciphertext { c: BigUint::zero() };
        let r = sk.decrypt(&bad);
        assert!(matches!(r, Err(HeError::InvalidCiphertext)));
    }

    #[test]
    fn test_chained_homomorphic_addition_five_values() {
        let sk = small_keypair();
        let mut rng = StdRng::seed_from_u64(10);
        let vals = [10u32, 20, 30, 40, 50];
        let mut acc = sk.public.encrypt(&BigUint::zero(), &mut rng).unwrap();
        for v in vals {
            let ct = sk.public.encrypt(&BigUint::from(v), &mut rng).unwrap();
            acc = sk.public.add(&acc, &ct);
        }
        let total = sk.decrypt(&acc).unwrap();
        assert_eq!(total, BigUint::from(150u32));
    }

    #[test]
    fn test_generate_512_bit_keypair_and_roundtrip() {
        let sk = medium_keypair(42);
        // Ensure modulus length is close to 512 bits (allow ±2 bits slop).
        let bits = sk.public.n.bits();
        assert!(bits >= 510 && bits <= 514, "unexpected n bits={bits}");
        let mut rng = StdRng::seed_from_u64(43);
        let m = BigUint::from(12345u32);
        let ct = sk.public.encrypt(&m, &mut rng).unwrap();
        assert_eq!(sk.decrypt(&ct).unwrap(), m);
    }

    #[test]
    fn test_miller_rabin_small_primes() {
        let mut rng = StdRng::seed_from_u64(11);
        for p in [2u32, 3, 5, 7, 11, 13, 17, 97, 101, 199, 257, 65537] {
            assert!(
                is_probable_prime(&BigUint::from(p), 20, &mut rng),
                "{p} should be prime"
            );
        }
        for n in [4u32, 9, 15, 21, 25, 100, 1024, 65535] {
            assert!(
                !is_probable_prime(&BigUint::from(n), 20, &mut rng),
                "{n} should be composite"
            );
        }
    }

    #[test]
    fn test_mod_inv_correctness() {
        let n = BigUint::from(323u32);
        // gcd(17, 323) = 17 — NOT invertible.
        assert!(mod_inv(&BigUint::from(17u32), &n).is_none());
        // 7 * 277 = 1939 = 6*323 + 1 → 7^-1 mod 323 = 277.
        let inv = mod_inv(&BigUint::from(7u32), &n).unwrap();
        assert_eq!(inv, BigUint::from(277u32));
    }
}

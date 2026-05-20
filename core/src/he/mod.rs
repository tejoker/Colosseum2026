//! Paillier homomorphic encryption (Tier 2, Sprint 13-14).
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
//! # What this module is
//!
//! Additively-homomorphic public-key encryption (Paillier 1999). Given
//! ciphertexts `c1 = Enc(m1)` and `c2 = Enc(m2)`, the server can compute
//! `c3 = c1 * c2 mod n^2 = Enc(m1 + m2 mod n)` **without** knowing the
//! private key. Scalar multiplication is `Enc(m)^k = Enc(m * k mod n)`.
//!
//! # What this module is NOT
//!
//! - Threshold Paillier (multi-party key generation).
//! - Damgård-Jurik (larger plaintext space).
//! - BGV/BFV/CKKS lattice-based HE (different math entirely).
//! - Constant-time arithmetic. We use `num-bigint` which is **not**
//!   constant-time. Side channels are not in scope for this iteration.
//!
//! # Use case
//!
//! "Secret sum" aggregation across customers: each customer encrypts a
//! local statistic with the cohort's public key, the server homomorphically
//! sums the ciphertexts, and decrypts only the aggregate. Per-customer
//! values never appear in plaintext on the server.
//!
//! See `docs/homomorphic-encryption.md` for the full production checklist.

pub mod encoding;
pub mod paillier;
pub mod serde_impl;

pub use encoding::{decode_f64, encode_f64};
pub use paillier::{Ciphertext, HeError, PaillierPrivateKey, PaillierPublicKey};

/**
 * Paillier homomorphic-encryption client (Sprint 13-14, Tier 2).
 *
 * # NEEDS_CRYPTO_REVIEW
 *
 * This implementation has **not** been audited by a cryptographer.
 * Suitable for development and demo only. Production deployments require
 * third-party review of:
 *   (a) modular arithmetic correctness,
 *   (b) random sampling distribution,
 *   (c) message space encoding,
 *   (d) ciphertext re-randomization,
 *   (e) side-channel resistance.
 *
 * # Scope
 *
 * - Encryption + homomorphic ops on ciphertexts using ES2020 native BigInt.
 * - **No key generation client-side.** Operators generate keys server-side
 *   under HSM/Vault custody. Customers only encrypt + submit.
 * - **No decryption client-side.** Private keys never leave the server.
 *
 * # Wire format
 *
 * `PaillierPublicKey` is the JSON shape produced by the Rust serde
 * serialization of `core::he::paillier::PaillierPublicKey`. The `n`,
 * `n_squared`, and `g` fields arrive as base-10 decimal strings (the
 * num-bigint default). Callers can also pass native BigInt values.
 */

import { webcrypto } from "node:crypto";

/**
 * Public key shape matching the server-side `PaillierPublicKey` JSON.
 *
 * Numeric fields accept either decimal strings (the on-wire form) or
 * native bigints (when assembled in-process).
 *
 * NEEDS_CRYPTO_REVIEW: validation of `n`, `n_squared`, `g` consistency
 * is NOT performed here. Callers MUST verify the key was issued by a
 * trusted operator and that `n_squared === n * n` and `g === n + 1`.
 */
export interface PaillierPublicKey {
    n: bigint | string;
    n_squared: bigint | string;
    g: bigint | string;
}

/** Paillier ciphertext. Lives in Z_{n^2}*. */
export interface Ciphertext {
    c: bigint;
}

/** Convert a key's `bigint | string` field to a `bigint`. */
function asBigInt(v: bigint | string): bigint {
    return typeof v === "bigint" ? v : BigInt(v);
}

/** Normalise a public key so every field is a bigint. */
function normalise(pk: PaillierPublicKey): {
    n: bigint;
    n_squared: bigint;
    g: bigint;
} {
    return {
        n: asBigInt(pk.n),
        n_squared: asBigInt(pk.n_squared),
        g: asBigInt(pk.g),
    };
}

/**
 * Modular exponentiation by repeated squaring. Returns `base^exp mod m`.
 *
 * NEEDS_CRYPTO_REVIEW: NOT constant-time. The branch on the low bit of
 * `exp` leaks via timing; that is acceptable for client-side encryption
 * (the exponent here is the public `n`, not secret material), but it
 * would be unacceptable for decryption — which we do NOT perform.
 */
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
    if (m === 1n) return 0n;
    let result = 1n;
    let b = base % m;
    if (b < 0n) b += m;
    let e = exp;
    while (e > 0n) {
        if ((e & 1n) === 1n) {
            result = (result * b) % m;
        }
        e >>= 1n;
        b = (b * b) % m;
    }
    return result;
}

/** Extended GCD for the modular-inverse check inside sampling. */
function gcd(a: bigint, b: bigint): bigint {
    let x = a < 0n ? -a : a;
    let y = b < 0n ? -b : b;
    while (y > 0n) {
        const t = y;
        y = x % y;
        x = t;
    }
    return x;
}

/** Bit length of a non-negative bigint. */
function bitLength(v: bigint): number {
    if (v === 0n) return 0;
    // Use the decimal/hex string trick to avoid an O(bits) loop.
    return v.toString(2).length;
}

/**
 * Random bigint uniformly in [1, n) with gcd(r, n) = 1. Uses
 * `crypto.getRandomValues` for the underlying bytes.
 *
 * NEEDS_CRYPTO_REVIEW: rejection sampling, not constant-time. For 2048-bit
 * `n` with the standard prime distribution the rejection rate is
 * overwhelmingly small (≈ 1/p + 1/q). 256 retries always succeeds in
 * practice. Cryptographer should confirm the rejection distribution is
 * unbiased and that we're not accidentally leaking through retries.
 */
function sampleZnStar(n: bigint): bigint {
    const bits = bitLength(n);
    const bytes = Math.ceil(bits / 8);
    for (let attempt = 0; attempt < 256; attempt++) {
        const buf = new Uint8Array(bytes);
        // Node 16+ exposes webcrypto; browsers expose self.crypto.
        const cryptoApi: { getRandomValues(b: Uint8Array): Uint8Array } =
            ((globalThis as any).crypto as { getRandomValues(b: Uint8Array): Uint8Array }) ??
            (webcrypto as unknown as {
                getRandomValues(b: Uint8Array): Uint8Array;
            });
        cryptoApi.getRandomValues(buf);
        // Mask high bits past `bits`.
        const extra = bytes * 8 - bits;
        if (extra > 0) {
            buf[0] = buf[0] & ((1 << (8 - extra)) - 1);
        }
        let r = 0n;
        for (const b of buf) {
            r = (r << 8n) | BigInt(b);
        }
        if (r >= 1n && r < n && gcd(r, n) === 1n) {
            return r;
        }
    }
    throw new Error("rejection sampling exhausted retries");
}

/**
 * Encrypt a message `m` in [0, n).
 *
 * Uses the textbook g = n+1 simplification:
 *   c = (1 + m * n) * r^n  mod n^2,  with r ∈ Z_n*.
 *
 * NEEDS_CRYPTO_REVIEW: rejection sampling on r, not constant-time on
 * `m * n` or the modular exponentiation. Side-channel resistance is out
 * of scope for the client wrapper.
 */
export function encrypt(message: bigint, pk: PaillierPublicKey): Ciphertext {
    const { n, n_squared } = normalise(pk);
    if (message < 0n || message >= n) {
        throw new Error("message out of range [0, n)");
    }
    const r = sampleZnStar(n);
    const onePlusMn = (1n + message * n) % n_squared;
    const rToN = modPow(r, n, n_squared);
    const c = (onePlusMn * rToN) % n_squared;
    return { c };
}

/**
 * Homomorphic addition: Enc(a) ⊕ Enc(b) = Enc(a + b mod n).
 *
 * NEEDS_CRYPTO_REVIEW: the result is **not** re-randomized. Publication
 * paths that expose intermediate sums should call [`rerandomize`].
 */
export function add(
    a: Ciphertext,
    b: Ciphertext,
    pk: PaillierPublicKey,
): Ciphertext {
    const { n_squared } = normalise(pk);
    return { c: (a.c * b.c) % n_squared };
}

/**
 * Scalar multiplication: Enc(a) ⊗ k = Enc(a * k mod n).
 *
 * NEEDS_CRYPTO_REVIEW: not re-randomized; see [`add`].
 */
export function mul_scalar(
    a: Ciphertext,
    k: bigint,
    pk: PaillierPublicKey,
): Ciphertext {
    const { n_squared } = normalise(pk);
    if (k < 0n) {
        throw new Error("scalar must be non-negative; use modular inverse for negatives");
    }
    return { c: modPow(a.c, k, n_squared) };
}

/**
 * Re-randomize a ciphertext: produce a fresh-looking encryption of the same
 * plaintext by multiplying with a fresh Enc(0).
 *
 * NEEDS_CRYPTO_REVIEW: rejection sampling. See [`encrypt`].
 */
export function rerandomize(ct: Ciphertext, pk: PaillierPublicKey): Ciphertext {
    const { n, n_squared } = normalise(pk);
    const r = sampleZnStar(n);
    const rToN = modPow(r, n, n_squared);
    return { c: (ct.c * rToN) % n_squared };
}

/**
 * Encode a ciphertext as URL-safe base64 (no padding). Matches the
 * server-side `core::he::serde_impl::ciphertext_to_b64`.
 */
export function ciphertextToB64(ct: Ciphertext): string {
    return bigintToB64(ct.c);
}

/** Parse a ciphertext from URL-safe base64 (no padding). */
export function ciphertextFromB64(s: string): Ciphertext {
    return { c: b64ToBigint(s) };
}

function bigintToB64(v: bigint): string {
    if (v < 0n) throw new Error("negative ciphertext");
    let hex = v.toString(16);
    if (hex.length % 2 !== 0) hex = "0" + hex;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    let b64 = Buffer.from(bytes).toString("base64");
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64ToBigint(s: string): bigint {
    let std = s.replace(/-/g, "+").replace(/_/g, "/");
    while (std.length % 4 !== 0) std += "=";
    const bytes = Buffer.from(std, "base64");
    if (bytes.length === 0) throw new Error("empty ciphertext");
    let hex = "";
    for (const b of bytes) {
        hex += b.toString(16).padStart(2, "0");
    }
    return BigInt("0x" + hex);
}

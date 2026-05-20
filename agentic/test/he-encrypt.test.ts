/**
 * Sprint 13-14 Tier 2 — Paillier client smoke tests.
 *
 * # NEEDS_CRYPTO_REVIEW
 *
 * This implementation has **not** been audited by a cryptographer.
 * Suitable for development and demo only. Production deployments require
 * third-party review of: modular arithmetic correctness, random sampling
 * distribution, message space encoding, ciphertext re-randomization,
 * and side-channel resistance.
 *
 * Standalone runner — `tsc` then `node dist/test/he-encrypt.test.js`.
 * Same style as `local-aggregate.test.ts`.
 */

import {
    paillierAdd,
    paillierEncrypt,
    paillierMulScalar,
    paillierModPow,
    ciphertextToB64,
    ciphertextFromB64,
    type PaillierPublicKey,
} from "../src";

let passed = 0;
let failed = 0;

function assert(cond: boolean, msg: string) {
    if (cond) {
        console.log(`  [ok] ${msg}`);
        passed++;
    } else {
        console.error(`  [FAIL] ${msg}`);
        failed++;
    }
}

/**
 * Test keypair matching the Rust-side small keypair: p=17, q=19, n=323.
 * NEEDS_CRYPTO_REVIEW: NOT secure — used to exercise the algebra only.
 */
const TEST_KEY: PaillierPublicKey = {
    n: 323n,
    n_squared: 323n * 323n,
    g: 324n,
};

/**
 * Server-side decryption oracle for the test. Mirrors
 * `core::he::paillier::PaillierPrivateKey::decrypt` with the same algebra:
 *   m = L(c^lambda mod n^2) * mu  mod n,
 * with lambda = lcm(16, 18) = 144 and mu = 144^-1 mod 323.
 *
 * NEEDS_CRYPTO_REVIEW: tests only — never embed a private key in client code.
 */
function decryptOracle(c: bigint): bigint {
    const n = 323n;
    const n2 = n * n;
    const lambda = 144n;
    // 144^-1 mod 323 = 9 (verified: 144 * 9 = 1296 = 4*323 + 4 — wait, recompute)
    // Use extended GCD inline:
    const mu = modInv(lambda, n);
    const u = paillierModPow(c, lambda, n2);
    // L(u) = (u - 1) / n
    const lU = (u - 1n) / n;
    return (lU * mu) % n;
}

function modInv(a: bigint, m: bigint): bigint {
    // Extended Euclidean.
    let [oldR, r] = [a, m];
    let [oldS, s] = [1n, 0n];
    while (r !== 0n) {
        const q = oldR / r;
        [oldR, r] = [r, oldR - q * r];
        [oldS, s] = [s, oldS - q * s];
    }
    if (oldR !== 1n) throw new Error("not invertible");
    return ((oldS % m) + m) % m;
}

async function testEncryptProducesCiphertextInRange() {
    const m = 42n;
    const ct = paillierEncrypt(m, TEST_KEY);
    assert(ct.c > 0n, "ciphertext c > 0");
    const n2 = TEST_KEY.n_squared as bigint;
    assert(ct.c < n2, "ciphertext c < n^2");
    const pt = decryptOracle(ct.c);
    assert(pt === m, `decrypt(encrypt(${m})) === ${m}, got ${pt}`);
}

async function testHomomorphicAddDecryptsToSum() {
    const a = 30n;
    const b = 50n;
    const ca = paillierEncrypt(a, TEST_KEY);
    const cb = paillierEncrypt(b, TEST_KEY);
    const csum = paillierAdd(ca, cb, TEST_KEY);
    const pt = decryptOracle(csum.c);
    assert(pt === 80n, `Enc(30) + Enc(50) decrypts to 80, got ${pt}`);
}

async function testMulScalarDecryptsToProduct() {
    const a = 7n;
    const k = 11n;
    const ca = paillierEncrypt(a, TEST_KEY);
    const cprod = paillierMulScalar(ca, k, TEST_KEY);
    const pt = decryptOracle(cprod.c);
    assert(pt === 77n, `Enc(7) * 11 decrypts to 77, got ${pt}`);
}

async function testCiphertextB64Roundtrip() {
    const ct = paillierEncrypt(99n, TEST_KEY);
    const b64 = ciphertextToB64(ct);
    const ct2 = ciphertextFromB64(b64);
    assert(ct.c === ct2.c, "ciphertext base64 round-trips");
}

async function testEncryptRejectsOutOfRange() {
    let threw = false;
    try {
        paillierEncrypt(500n, TEST_KEY);
    } catch (_e) {
        threw = true;
    }
    assert(threw, "encrypt rejects m >= n");
}

async function main() {
    console.log("\n  Paillier client tests");
    console.log("  ─────────────────────");
    try {
        await testEncryptProducesCiphertextInRange();
        await testHomomorphicAddDecryptsToSum();
        await testMulScalarDecryptsToProduct();
        await testCiphertextB64Roundtrip();
        await testEncryptRejectsOutOfRange();
        console.log("\n══════════════════════════════════════════════════");
        console.log(`  Results: ${passed} passed, ${failed} failed`);
        console.log("══════════════════════════════════════════════════");
        if (failed > 0) process.exit(1);
    } catch (e) {
        const err = e as Error;
        console.error("\n  [FATAL]", err.message);
        console.error(err.stack);
        process.exit(1);
    }
}

void main();

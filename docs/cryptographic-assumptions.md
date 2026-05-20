# Cryptographic Assumptions

Per-primitive ledger: what we assume, where used, security margin, what breaks if assumption fails. Pentest readers should treat this as the truth table for every "is X really secure?" question. Write-up style is terse on purpose — each row maps one primitive to one citable code path.

This doc complements `docs/threat-model.md`. The threat model says *what* attacks we resist; this doc says *why the math holds*, and where the cliff is if the math does not.

---

## 1. Ed25519 (EdDSA over Curve25519)

| Field | Value |
|---|---|
| Assumption | Elliptic-curve discrete log over Curve25519 (twisted Edwards form) is hard. |
| Source | RFC 8032; Bernstein et al. 2011. |
| Key size | 32 B secret scalar, 32 B public point. |
| Expected margin | ≈ 128-bit. |
| Used for | Agent PoP keys (`pop_public_key_b64u`, `core/src/agent.rs:1429`), A-JWT signatures (`core/src/ajwt_support.rs`), per-call DPoP-style sigs (`core/src/agent.rs:1587`), per-receipt action-envelope sigs, operator-rooted attestation (`Ed25519Self` in `core/src/attestation.rs`). |
| If broken | Any captured public key forges signatures. Every leash that depends on PoP is bypassed. Action receipts can be re-signed by an attacker holding only the public key — receipts become repudiable. Migrate to PQ signatures (Dilithium / Falcon) before this happens. |

## 2. HMAC-SHA256

| Field | Value |
|---|---|
| Assumption | SHA-256 compression function is a PRF; HMAC construction inherits PRF security. |
| Source | RFC 2104; Bellare 2006. |
| Key size | Min 32 B in production (enforced for `SAURON_ADMIN_KEY` / `SAURON_JWT_SECRET`, see `core/src/admin.rs:99-107`). |
| Expected margin | ≈ 128-bit (forgery), ≈ 256-bit (key recovery). |
| Used for | Admin auth bearer tokens (`core/src/admin.rs::build_admin_auth_config`), session tokens, JWT signing for A-JWTs, OPRF-derived per-tenant secrets. |
| If broken | All admin / session / JWT secrets become trivially forgeable. Switch to KMAC / Blake3-MAC. |
| Side-channels | Comparison is via `subtle::ConstantTimeEq` (no timing oracle). |

## 3. SHA-256

| Field | Value |
|---|---|
| Assumption | Collision resistance ≈ 128-bit (birthday); pre-image resistance ≈ 256-bit. |
| Source | NIST FIPS 180-4. |
| Used for | `agent_checksum` (`core/src/agent_checksum.rs`), per-call body digest, Merkle tree leaves (`core/src/merkle.rs`), Bitcoin OTS internal hashing. |
| If broken | Collision attack lets a forger swap agent config (system prompt / tools / model) without detection. Merkle proofs for action receipts become forgeable — receipts can be backdated or substituted. Migrate to SHA-3 or Blake3. |

## 4. Bitcoin OpenTimestamps (OTS) anchoring

| Field | Value |
|---|---|
| Assumption | Bitcoin proof-of-work consensus is honest-majority (>50% hashrate honest); SHA-256d collision resistance holds. |
| Source | Nakamoto 2008; OpenTimestamps spec; we use the calendar/aggregation architecture. |
| Used for | Tamper-evident anchoring of agent-action merkle roots (`core/src/bitcoin_anchor.rs`). |
| Expected margin | Inherits Bitcoin's. Confirmation latency ≈ 1 hour for the upgraded full attestation; calendar receipts arrive in seconds. |
| If broken | After-the-fact rewrite of the agent-action audit log becomes feasible. Until then, every receipt-id leaf is bound to a Bitcoin block timestamp. |
| Operator note | Calendar downtime ≠ broken security, just delayed upgrade. See `docs/disaster-recovery.md` §Bitcoin-OTS-calendar-unavailable. |

## 5. Solana Memo anchoring

| Field | Value |
|---|---|
| Assumption | Solana consensus (Proof-of-History + Tower BFT) is correct under <33% Byzantine stake. |
| Source | Yakovenko 2018; current Solana mainnet validator set. |
| Used for | Low-latency confirmation of agent-action merkle roots in parallel to Bitcoin OTS (`core/src/solana_anchor.rs`). Finalized ≈ 30 s. |
| If broken | Solana-side audit log becomes mutable, but the Bitcoin-side anchor still holds. Defence-in-depth: tampering requires forging *both* chains, which is the design intent. |
| Cost note | Memo writes cost SOL; budget envelope documented in `docs/operations.md`. |

## 6. OPRF on the Ristretto255 group

| Field | Value |
|---|---|
| Assumption | Decisional Diffie-Hellman over the prime-order Ristretto255 group; BLAKE2-based PRF unlinkability. |
| Source | de Valence 2017 (Ristretto); Jarecki–Krawczyk–Xu 2018 (HashDH OPRF). |
| Expected margin | ≈ 128-bit. |
| Used for | Per-tenant deterministic identifier derivation from passphrases (`core/src/oprf.rs`); ring identity unlinkability. The server holds `SAURON_OPRF_SEED`; clients blind their input so the server learns nothing about it during evaluation. |
| If broken | An attacker recovering the OPRF scalar can deterministically derive every per-tenant key-image from any input — effectively cross-link all users on the system. |
| Operator note | `SAURON_OPRF_SEED` is loaded with the same envelope-encryption pipeline as `SAURON_JWT_SECRET` (`core/src/state.rs:170-254`, `core/src/secret_provider.rs`). Rotation = breaking change; see `docs/key-rotation.md`. |

## 7. Merkle trees with Poseidon-in-circuit / SHA-256-out-of-circuit

| Field | Value |
|---|---|
| Assumption | Out-of-circuit: SHA-256 collision + pre-image resistance (same as §3). In-circuit (ZK proofs): Poseidon hash is collision-resistant and behaves as a random oracle in the algebraic group model. |
| Source | Grassi et al. 2021 (Poseidon); circom community analysis. |
| Used for | Action-log merkle commitments (`core/src/merkle.rs`); ZK circuits at `zkp/circuits/Action*.circom`. |
| If broken | Same blast radius as §3 plus: any ZK proof can claim arbitrary leaves were committed. |
| Open issue | Poseidon parameters in our circuits should be cross-checked against the latest published preimage-resistance bounds before pentest. Tracked. |

## 8. Groth16 zero-knowledge proofs

| Field | Value |
|---|---|
| Assumption | Knowledge soundness in the Generic Group Model + Algebraic Group Model. Per-circuit *trusted setup* required. |
| Source | Groth 2016; AGM bounds Fuchsbauer–Kiltz–Loss 2018. |
| Used for | Aggregated stats proofs (`core/src/aggregation/verify.rs`, `core/src/zk_verifier.rs`), action-log proofs. |
| Expected margin | ≈ 128-bit *iff* the trusted setup was honest (no party kept the toxic waste). |
| **Honest gap** | **Today our verification keys come from a single-party local setup (`zkp/ceremony/dev_setup.sh`). Anyone with filesystem access to that dev machine can forge proofs that pass verification.** Production deployment requires the multi-party ceremony documented at `zkp/ceremony/README.md`. Until that ceremony runs, all ZK claims are unsound in the adversarial sense. We rely on the cross-checks (Bitcoin/Solana anchors, server-side spend ledger, policy re-evaluation) for actual security. |
| If broken | An attacker with the trapdoor forges arbitrary proofs of arbitrary statements. The ZK layer becomes window-dressing. |

## 9. TPM 2.0 attestation

| Field | Value |
|---|---|
| Assumption | TPM vendor (Infineon / STMicro / Microsoft / Intel / AMD / IBM / Nuvoton) PKI root is honest; the TPM chip itself generates keys with the private half non-exportable; firmware boundary holds. |
| Source | TCG TPM 2.0 Library Spec; per-vendor EK cert practice statements. |
| Used for | Optional `Tpm2Quote` attestation kind on agent registration (`core/src/agent.rs:476`, `core/src/attestation.rs:823`). Recognised today; full vendor cert chain verifier roadmapped. |
| If broken | Operator can lie about agent-host integrity. Falls back to `Ed25519Self` (operator-rooted) trust, which is weaker but still cryptographically bound. |

## 10. AWS Nitro Enclaves

| Field | Value |
|---|---|
| Assumption | AWS Nitro PKI root + AWS not Byzantine; enclave firmware boundary holds; COSE_Sign1 attestation format is correctly parsed. |
| Source | AWS Nitro Enclaves whitepaper; AWS root cert pinned at deploy time. |
| Used for | Optional `NitroEnclave` attestation kind (`core/src/attestation.rs`). Recognised today; full verifier roadmapped. |
| If broken | AWS-hosted operators lose the host-integrity guarantee; falls back to `Ed25519Self`. Non-AWS operators unaffected. |
| Lock-in note | Operators wanting cloud-agnostic attestation use `Tpm2Quote` once that path lands. We are not AWS-only. |

## 11. Random number generation

| Field | Value |
|---|---|
| Assumption | The OS CSPRNG is healthy (sufficient entropy, no backdoor). |
| Used for | Ed25519 keypair generation, JTI / nonce / per-call nonce minting, OPRF blinding factors, anchor batch IDs. |
| If broken | Every keypair, JTI, nonce becomes predictable. Catastrophic. |
| Operator note | Deploy on hosts with `/dev/urandom` properly seeded (post-boot entropy collection). Sane containerised platforms (kvm + RDRAND) are fine. Avoid VM templates that snapshot before entropy seeding. |

---

## Honest gaps

1. **Groth16 trusted setup not yet run.** All current vk files are dev-only. Production unsoundness is documented in §8 and `zkp/ceremony/README.md`.
2. **Vendor attestation verifiers (TPM2 / SGX / SEV-SNP / Apple / Nitro) recognised but not yet enforcing the full cert chain.** `Ed25519Self` is the only fully verified path today (`core/src/attestation.rs`).
3. **Quantum threat is out of scope.** Ed25519 + Ristretto + secp256k1 are all quantum-broken under Shor. Migration to PQ signatures is a future-sprint deliverable.
4. **Poseidon parameter audit pending.** Used inside ZK circuits; relies on parameters generated upstream. Spot-check before external pentest.

---

## What a pentester should hammer first

1. Replay / freshness boundaries (covered by `redteam/src/scenarios/replay-*.ts`).
2. Cross-tenant leakage of any of the primitives above (`redteam/src/scenarios/tenant-*.ts`).
3. ZK proof acceptance under malformed / cross-vk / cross-tenant inputs (`redteam/src/scenarios/proof-*.ts`).
4. Constant-time guarantees of HMAC compare paths (manual / `hyperfine`-style timing).
5. Bitcoin / Solana anchor proofs round-tripped against an external verifier (`ots verify`, `solana getTransaction`).

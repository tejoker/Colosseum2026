# SauronID ZK Trusted Setup Ceremony

This directory describes how to produce **production** Groth16 verification
keys for the action-log circuits in `zkp/circuits/Action*.circom` and
`zkp/circuits/SignedLogEntry.circom`.

> **WARNING — DEV KEYS ONLY**
>
> The keys checked into `zkp/circuits/build/<circuit>/verification_key.dev.json`
> and `*.dev.zkey` come from a single-party local setup
> (`dev_setup.sh`). **They are not safe for production.** Anyone who reads the
> file system of the dev machine can forge proofs that pass verification.
>
> Production keys MUST come from a multi-party ceremony where at least
> `contributors_required` independent parties each contribute entropy, AND
> at least one of them deletes their toxic waste. See
> `circuits-list.json` for per-circuit security tiers.

## File-naming convention

| Suffix                  | Meaning                                                     |
|-------------------------|-------------------------------------------------------------|
| `_final.dev.zkey`       | DEV proving key — local setup only                          |
| `.dev.vkey.json`        | DEV verification key — local setup only                     |
| `_final.zkey`           | PROD proving key — multi-party ceremony output              |
| `_verification_key.json`| PROD verification key — multi-party ceremony output         |

The Rust verifier (`core/src/zk_verifier.rs`) and the TS verifier
(`zkp/sdk/src/verifier.ts`) both try the PROD path first and fall back to the
DEV path. Replace DEV with PROD by dropping the new files in the same
directory and removing the `*.dev.*` artifacts.

## Ceremony procedure (PROD)

1. **Phase 1 — Powers of Tau (universal, circuit-independent).** Reuse a
   well-known existing ceremony output (e.g. perpetual powers of tau, party
   of `≥ 70` contributors, BN254 curve). Do not run this from scratch unless
   you have months and ≥ 30 contributors.

2. **Phase 2 — Per-circuit contribution.** For each circuit:
   1. `snarkjs groth16 setup <circuit>.r1cs powersOfTau28_hez_final_<n>.ptau <circuit>_0000.zkey`
   2. Each contributor `i` runs `contribute.sh <circuit> <i> <random entropy>`.
   3. Each contributor publishes their attestation (output of
      `verify_contribution.sh`) to a public log.
   4. After the last contributor, `snarkjs zkey beacon <circuit>_<n>.zkey
      <circuit>_final.zkey <hex_beacon> <num_iters>` finalises the key with a
      public beacon (e.g. a recent Bitcoin block hash).
   5. Extract the verification key: `snarkjs zkey export verificationkey
      <circuit>_final.zkey <circuit>_verification_key.json`.

3. **Attestation.** Publish the final zkey hash, every contributor's
   attestation, and the beacon source in a tamper-evident log
   (e.g. opentimestamps + git tag).

4. **Acceptance criteria.** At least `contributors_required` independent
   contributors AND at least one of them produces an audited destruction
   record of their toxic waste (random tape).

## Files in this directory

- `dev_setup.sh` — runs `snarkjs groth16 setup` locally to produce the DEV
  keys. Convenient for hackathon demos; **do not ship in production.**
- `contribute.sh` — stub showing the shape of a real Phase 2 contribution.
  Does not run an actual multi-party ceremony.
- `verify_contribution.sh` — stub for verifying another contributor's
  attestation.
- `circuits-list.json` — declares each circuit's security tier and the number
  of contributors required for prod.

## Threat model

A malicious or compromised setup gives the attacker the ability to forge
proofs for **any** statement under the affected verification key. For
SauronID action-log proofs this would let the attacker fabricate compliance
proofs (sum-bound, time-window, etc.) without ever performing the underlying
actions. Mitigation: multi-party ceremony with public beacons; rotate the
verification key on a published schedule.

# ZK Proofs over the Agent-Action Log

Sprint 4 introduces a family of Groth16 circuits that prove properties of the
`agent_action_receipts` Merkle tree (the "action log") without revealing the
underlying entries. This document is the reference for what each circuit
proves, the SDK + Rust verifier surface, and the dev-vs-production trusted
setup distinction.

> **DEV verification keys only.** The keys produced by `zkp/ceremony/dev_setup.sh`
> live under `*.dev.zkey` / `*.dev.vkey.json`. A single-party local setup is
> **not safe for production** — anyone with read access to the machine running
> the setup can forge proofs. Production deployments MUST replace these with
> keys produced by a multi-party ceremony described in
> `zkp/ceremony/README.md`.

## What lives where

- `zkp/circuits/SignedLogEntry.circom`, `Action*.circom` — new Circom 2.1.6
  circuits over the Poseidon-hashed action log.
- `zkp/circuits/MerkleInclusion.circom`, `AgeVerification.circom`,
  `CredentialVerification.circom` — legacy circuits (Age is load-bearing per
  the previous audit; Credential is deferred for deletion until callers
  migrate to `action-log.ts`).
- `zkp/sdk/src/action-log.ts` — TypeScript prover + verifier classes
  (`ActionLogProver`, `ActionLogVerifier`, `proveCompliance`).
- `zkp/sdk/src/credential.ts` — `@deprecated`, re-exports the action-log API.
- `core/src/zk_verifier.rs` — server-side Rust verifier (process-spawn
  approach for M1; see file header for the dep-choice rationale).
- `zkp/ceremony/` — README, DEV setup script, stub Phase-2 contribution scripts.

## Per-circuit reference

The action log is modeled as a Poseidon Merkle tree whose leaves are
`Poseidon(entry[0..N])` for a fixed-arity `entry` vector. Default depth in
every circuit's `main` declaration is 20 (≤ 2^20 entries per tree). All
circuits emit a single `valid` output signal at index 0 of the public-signals
array, followed by their declared public inputs in declaration order.

### `SignedLogEntry(levels)`

Proves: "I know a signed log entry `(h, sig)` such that
`MerkleVerify(root, h, path) ∧ EdDSAPoseidon(pubkey, h, sig)`."

| Side    | Signal                                       |
|---------|----------------------------------------------|
| Public  | `root`, `pubkeyAx`, `pubkeyAy`               |
| Private | `leafHash`, `sigR8x`, `sigR8y`, `sigS`, `pathElements[20]`, `pathIndices[20]` |

Use when: you need to demonstrate that a specific log entry was signed by a
known agent **and** committed to the log, without revealing the entry's
fields. Generalises the legacy `CredentialVerification` circuit.

### `ActionRangeProof(levels, entryFields)`

Proves: "For a committed entry with field X (e.g. `amount_minor`),
`a ≤ X ≤ b`."

| Side    | Signal                                       |
|---------|----------------------------------------------|
| Public  | `root`, `a`, `b`, `entryIndex`               |
| Private | `entry[6]`, `pathElements[20]`, `pathIndices[20]`, `fieldSelector[6]` (one-hot) |

Use when: prove a per-action bound (e.g., `0 ≤ amount ≤ 50000`) without
revealing the amount. The one-hot `fieldSelector` picks which field of the
entry vector is the range subject — the circuit verifies the selector sums to
one bit. Comparators are 32-bit.

### `ActionSumBound(levels, entryFields, N)`

Proves: "Σ amount(entry_k) ≤ budget over a contiguous range of N entry indices."

| Side    | Signal                                       |
|---------|----------------------------------------------|
| Public  | `root`, `budget`, `iLo`, `iHi` (iHi = iLo + N − 1) |
| Private | `entries[N=4][6]`, `pathElements[N][20]`, `pathIndices[N][20]`, `amountSelector[6]` |

Use when: prove a periodic budget constraint (e.g., "this agent spent ≤ €1000
across actions 100..103"). The summation uses a 64-bit comparator so N×32-bit
amounts never overflow.

### `ActionSetMembership(levels, setLevels, entryFields)`

Proves: "The tool field of entry X is a member of the allowlist set
committed at `allowlistRoot`."

| Side    | Signal                                       |
|---------|----------------------------------------------|
| Public  | `root`, `allowlistRoot`, `entryIndex`        |
| Private | `entry[6]`, `entryPath*[20]`, `toolValue`, `toolSelector[6]`, `setPath*[10]` |

Use when: enforce a tool allowlist (e.g., "this agent only uses
`transfer.eur`, `transfer.usd`"). The allowlist set is committed as a
Merkle tree whose leaves are `Poseidon(toolValue, 1)` (the trailing `1`
prevents leaf-mid-tree-collision attacks).

### `ActionSetNonMembership(levels, setLevels, entryFields)`

Proves: "The tool field of entry X is NOT in the denylist set committed at
`denylistRoot`," via a sorted-pair gap proof.

| Side    | Signal                                       |
|---------|----------------------------------------------|
| Public  | `root`, `denylistRoot`, `entryIndex`         |
| Private | `entry[6]`, `entryPath*[20]`, `toolValue`, `toolSelector[6]`, `low`, `high`, `pairPath*[10]` |

The denylist tree must be built with leaves `Poseidon(low, high, 2)` sorted
ascending by `low`; the prover supplies the adjacent pair straddling
`toolValue` (`low < toolValue < high`). Sentinel leaves cover the lower /
upper field range.

### `ActionTimeWindow(levels, entryFields)`

Proves: "The timestamp field of entry X lies in `[start, end]`."

| Side    | Signal                                       |
|---------|----------------------------------------------|
| Public  | `root`, `start`, `end`, `entryIndex`         |
| Private | `entry[6]`, `path*[20]`, `timestampSelector[6]` |

Use when: prove an action happened within a specific period without revealing
its exact timestamp. 64-bit comparators (epoch seconds fit).

### `ActionCountInRange(levels, entryFields, N)`

Proves: "Among entries at indices `[iLo, iHi]`, the count of those with
field F equal to V is ≤ limit."

| Side    | Signal                                       |
|---------|----------------------------------------------|
| Public  | `root`, `F`, `V`, `limit`, `iLo`, `iHi`      |
| Private | `entries[N=4][6]`, `path*[N][20]`, `fieldSelector[6]`, `matchFlag[N]` |

`F` is a public commitment to which field is being counted; the circuit
binds it via `Poseidon(fieldSelector) == F` so the prover cannot lie about
which field is queried. `matchFlag[k]` is forced to equal `IsEqual(entry[F], V)`,
so the count cannot be undercounted by setting a flag to 0 on a matching
entry.

## When to use which

| Goal                                                            | Circuit                  |
|------------------------------------------------------------------|--------------------------|
| Prove a single signed log entry exists in the tree              | `SignedLogEntry`         |
| Show one action's amount is within a regulatory band            | `ActionRangeProof`       |
| Demonstrate a periodic budget ceiling was respected             | `ActionSumBound`         |
| Show only allowlisted tools were used                           | `ActionSetMembership`    |
| Show denylisted tools were never used                           | `ActionSetNonMembership` |
| Prove an action happened within a compliance window             | `ActionTimeWindow`       |
| Prove a rate limit on a specific field/value pair was respected | `ActionCountInRange`     |

## SDK surface

```ts
import {
    ActionLogProver,
    ActionLogVerifier,
    proveCompliance,
} from "@sauronid/sdk";

const prover = new ActionLogProver({ circuitsDir: "zkp/circuits/build" });
const verifier = new ActionLogVerifier({ verificationKeysDir: "zkp/circuits/build/keys" });

// Single-circuit example
const proof = await prover.proveRange(entry, path, 0n, 50000n, [1, 0, 0, 0, 0, 0]);
const ok = await verifier.verify(proof);

// Bundle of clauses
const proofs = await proveCompliance("agent-42", "2026-Q2", {
    sumBound: { entries, paths, budget: 100000n, amountSelector },
    timeWindow: { entry, path, start, end, timestampSelector },
}, { circuitsDir: "zkp/circuits/build" });
```

Each prover method returns an `ActionLogProof` envelope:

```ts
interface ActionLogProof {
    circuit: string;             // "ActionSumBound", etc.
    public_inputs: string[];     // canonical snarkjs order: [valid, ...declared]
    proof: ProofObject;          // { pi_a, pi_b, pi_c, protocol, curve }
}
```

## `proveCompliance` end-to-end

1. Caller passes an `agentId`, `period` label, and a partial `CompliancePolicy`
   object whose fields are the proofs they want bundled.
2. `proveCompliance` instantiates `ActionLogProver` once with `circuitsDir`.
3. For each populated clause it calls the matching `prove*` method.
4. The returned array of `ActionLogProof` envelopes can be uploaded to the
   server's `POST /v1/proofs/action-log/verify` endpoint one-by-one.

The function does not embed `agentId` or `period` in the proofs — the public
root binds them implicitly (each `(agentId, period)` pair commits to its own
action-log root in `core/src/agent_action_anchor.rs`).

## Server-side verification

`POST /v1/proofs/action-log/verify` (admin-gated):

```json
{
    "circuit": "ActionSumBound",
    "public_inputs": ["1", "12345...", "100000", "100", "103"],
    "proof_b64": "<base64 of the snarkjs proof JSON>",
    "vk_id": "ActionSumBound.dev.vk@v0",
    "expected_root_hex": "abcd1234... (32-byte hex)"
}
```

- Returns `200 OK` if the proof verifies AND `public_inputs[1]` (root) maps
  to `expected_root_hex`.
- Returns `400 Bad Request` for malformed payloads, root mismatch, or invalid
  proofs.
- Returns `404` if the verification key for `circuit` is missing.
- Returns `500` if the verifier subprocess fails to spawn or read its output.

The Rust implementation in `core/src/zk_verifier.rs` spawns `snarkjs verify`
under the hood (M1 dep-choice — see the file header for the rationale).

## Dev vs production ceremony

| Aspect                  | DEV (`dev_setup.sh`)              | PROD (multi-party)                 |
|-------------------------|-----------------------------------|------------------------------------|
| Setup parties           | 1 (this machine)                  | ≥ 3–8 (per `circuits-list.json`)   |
| Toxic-waste destruction | best-effort `head -c /dev/urandom`| audited destruction by every party |
| Beacon                  | none                              | public beacon (e.g. BTC block hash)|
| Filename                | `*_final.dev.zkey`, `*.dev.vkey.json` | `*_final.zkey`, `*_verification_key.json` |
| Threat model            | local-machine attacker can forge proofs | requires collusion of all ceremony parties |

The Rust + TS verifiers both look for the PROD filenames first and fall back
to DEV. Migration to PROD = drop the PROD files in the keys dir; the verifier
picks them up automatically and the DEV files can then be removed.

## Threat model

- **Trusted setup compromise.** Documented above. Mitigation: real ceremony.
- **Tree-depth overflow.** Default depth = 20 (≤ 1,048,576 entries). For
  larger trees, recompile circuits and re-run the ceremony at the new depth
  (the verification key embeds the depth).
- **One-hot selector forgery.** Every selector input is constrained:
  `selectorSum === 1` and per-bit binary constraints. A prover cannot
  fabricate a "field" that doesn't appear in the entry vector.
- **Count under-counting.** `ActionCountInRange` forces `matchFlag[k]` to
  equal `IsEqual(entry[F], V)`. A prover supplying a matching entry MUST set
  the flag to 1. Production use should pair this with a "cover every index
  in `[iLo, iHi]`" recursion (out of scope for M1).
- **Root binding.** The server's `/v1/proofs/action-log/verify` requires the
  caller to supply the expected root in hex and rejects mismatches before
  calling the heavy verifier — preventing wasted verification work on stale
  / cross-period proofs.
- **Subprocess injection.** The verifier rejects circuit names containing
  any character outside `[A-Za-z0-9_.-]` before constructing a filename.

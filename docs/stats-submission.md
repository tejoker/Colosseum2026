# Stats submission — transparent production proof

> Anti-cheat layer for cross-customer benchmarks.

## Production model

Production uses `POST /v1/stats/submit-transparent` and the pinned
`sauron-stats-v1` RISC Zero guest in `transparent-zk/`. There is no trusted
setup or proving-key ceremony. The client supplies every private signed action
envelope/receipt in the authoritative action-anchor interval; the guest
recomputes action hashes, every v2 leaf, the complete Merkle root and the
metric. The server resolves the checkpoint root, size and anchor from its own
database and verifies a native STARK receipt against the operator-pinned image
ID.

Supported production metrics are `success_rate`, `error_rate`,
`tool_call_count`, and USD-only `cost_total`. The public journal binds tenant,
checkpoint, action anchor, root, exact tree size, optional agent scope, metric,
value and period. Clients can verify the same receipt independently with
`sauron-transparent-verify`; they do not trust a SauronID success boolean.

`POST /v1/stats/submit` and the Circom/Groth16 material described below are
development/migration compatibility only and are refused in production.

## Legacy Circom model (development only)

Cross-tenant benchmarks are politically explosive: a vendor whose
"success rate" looks low has a strong incentive to massage the number
before it lands in a shared cohort view. SauronID's solution is the
**commit-then-prove** flow:

```
SDK side                              Server side
──────────                            ────────────
1. accumulate N action receipts
2. commit exactly four typed receipts
   to the circuit's Poseidon Merkle tree.
3. compute the metric locally over
   exactly the committed leaves.
4. produce a Groth16 proof
   "claimed_value is the honest
    aggregation of N receipts
    against root R".
5. finalize an anchored checkpoint
   for that root and tree size.
6. POST {stat, proof, checkpoint, …} ► 7. verify_stats_submission
                                         • payload sanity
                                         • metric_id ∈ provable set
                                         • public_inputs ↔ body bind
                                         • snarkjs subprocess
                                     8. upsert into customer_stats
                                     9. persist the statement hash in the
                                        dedicated stats receipt table; never
                                        mix an unsigned synthetic row into an
                                        action-proof Merkle batch.
                                    10. respond {stored, latency_ms,
                                                statement_hash}
```

The proof binds the claimed integer to a finalized, server-resolved checkpoint
root. It cannot inflate a count or fudge `n_records`: the circuit covers every
index 0..3 exactly once and requires both `n_records` and checkpoint
`tree_size` to equal four. The checkpoint timestamps and freezes the tenant's
commitment; it does **not** prove that the tenant included every real-world
receipt. Source completeness remains an ingestion/oracle assumption.

## Metric catalog (10)

| id                          | type        | field         | unit     | ZK provable today |
|-----------------------------|-------------|---------------|----------|:-----------------:|
| success_rate                | rate        | status        | fraction | yes               |
| latency_p50                 | percentile  | latency_ms    | ms       | no                |
| latency_p99                 | percentile  | latency_ms    | ms       | no                |
| error_rate                  | rate        | status        | fraction | yes               |
| tool_call_count             | count       | tool          | count    | yes               |
| unique_tools_used           | count       | tool          | count    | no                |
| cost_total                  | count (sum) | amount_usd    | usd      | yes               |
| policy_violations_blocked   | count       | status        | count    | no                |
| sessions_count              | count       | agent_id      | count    | no                |
| avg_session_duration        | average     | latency_ms    | seconds  | no                |

`sensitivity_l1` is documented per metric in
`agentic/src/stats/metric-catalog.ts` for Sprint 8's DP publisher.

### Why percentiles + distinct counts are not ZK-provable here

`StatsHonestComputation.circom` proves sums + counts + averages. A
percentile needs the prover to sort the witness then prove the k-th
element is the answer — that is a permutation-argument circuit. We
have it on the roadmap (see `zkp/ceremony/circuits-list.json`) but it
is **out of scope this sprint**. Distinct counts (unique_tools_used,
sessions_count) need a sorted-uniqueness gadget for the same reason.

For these four metrics the SDK either skips the submission (default)
or sends them through a trusted-input path with a WARNING label that
Sprint 8 cohort.rs / Sprint 9 dashboard render explicitly so consumers
know the entry is unverified.

## ZK circuit — `zkp/circuits/StatsHonestComputation.circom`

- Public inputs (snarkjs canonical order, after `valid`):
  ```
  [valid, root, metric_id, claimed_value, n_records, period_start, period_end,
   tree_size, tenant_hash, agent_hash]
  ```
- Private inputs:
  - `entries[4][7]` = `[status_bit, latency_ms, amount_milli_usd,
    tool_id, tenant_hash, agent_hash, created_at]`
  - `pathElements[N][20]`, `pathIndices[N][20]` — per-receipt Merkle path
- Constraint sketch:
  1. For each k ∈ 0..N-1: `Poseidon(entries[k])` must climb the supplied
     path to `root`.
  2. Compute the metric-specific (numerator, denominator) pair (see
     circuit doc-comment).
  3. Assert `claimed_value * denominator == numerator * 1000`. The ×1000
     is the fixed-point factor; the SDK's `toFixedPoint` reverses it.
  4. Bind every receipt to `tenant_hash`, optionally to `agent_hash`, and to
     the public reporting period.
  5. Assert `n_records == tree_size == N == 4`; paths are fixed to indices
     0..3, so the prover cannot omit or duplicate an index.

Depth bound: 20. The currently versioned circuit supports exactly four
receipts. Larger windows require a new circuit/version or a reviewed recursive
aggregation construction.

## Legacy server-side surface

### `POST /v1/stats/submit`

- Admin-gated.
- Body (JSON, `serde(deny_unknown_fields)`):

```json
{
  "tenant_id": "default",
  "agent_id_or_none": null,
  "metric_id": "success_rate",
  "claimed_value": 750,
  "n_records": 4,
  "period_start": 0,
  "period_end": 60,
  "merkle_root": "00000000000000000000000000000000000000000000000000000000000000ab",
  "proof_b64": "<base64-encoded snarkjs Groth16 proof JSON>",
  "vk_id": "StatsHonestComputation.dev.vk@v1",
  "checkpoint_id": "zkc_<server-issued-finalized-id>",
  "public_inputs": [
    "1", "<root-decimal>", "0", "750", "4", "0", "60", "4",
    "<tenant-hash-decimal>", "0"
  ]
}
```

- Response (200):

```json
{
  "stored": true,
  "latency_ms_verify": 87,
  "statement_hash": "<sha256-hex>"
}
```

- Errors:
  - `400 bad request` — malformed envelope, non-provable metric, body /
    public-inputs binding mismatch, proof rejected.
  - `404 not found` — verification key missing for the named circuit.
  - `500 internal server error` — verifier subprocess died (snarkjs
    binary missing from `$PATH`, etc.).

### `GET /v1/stats/cohort?metric_id=X&period_start=Y&period_end=Z`

- Admin-gated.
- Returns the cross-tenant raw cohort table for an operator view.
- **NOT** the DP-published view — that lives in Sprint 8
  (`core/src/dp/publish.rs`) and Sprint 9 (`dashboard/`).

## Worked curl example

Assumes the dev ceremony has produced the StatsHonestComputation
artefacts under `zkp/circuits/build/keys/`. The proof JSON below is a
placeholder — in practice the SDK produces it via
`StatsProver.proveStat` shelling out to snarkjs.

```bash
# 1. Submit
curl -sS -X POST http://localhost:8080/v1/stats/submit \
  -H 'authorization: Bearer dev' \
  -H 'content-type: application/json' \
  -H 'x-sauron-tenant-id: acme_corp' \
  -d @- <<'JSON'
{
  "tenant_id": "acme_corp",
  "agent_id_or_none": null,
  "metric_id": "success_rate",
  "claimed_value": 750,
  "n_records": 4,
  "period_start": 1715040000,
  "period_end": 1715644800,
  "merkle_root": "fa1afe1cafe0baadbeefcafefeedfacecafebabefeedfacebeefdeadc0debeef",
  "proof_b64": "eyJwaV9hIjpbIjEiLCIxIl0sInBpX2IiOltbIjEiXV0sInBpX2MiOlsiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0=",
  "vk_id": "StatsHonestComputation.dev.vk@v1",
  "public_inputs": [
    "1",
    "113078212145816597093331886104539600640",
    "0",
    "750",
    "4",
    "1715040000",
    "1715644800"
  ]
}
JSON

# Expected:
# {"stored":true,"latency_ms_verify":87,"statement_hash":"…"}

# 2. List cohort
curl -sS \
  -H 'authorization: Bearer dev' \
  "http://localhost:8080/v1/stats/cohort?metric_id=success_rate&period_start=1715040000&period_end=1715644800"

# Expected: {"rows":[{...}], "n":1}
```

## SDK auto-submission (weekly cron)

```ts
import { createWeeklyScheduler } from "@sauronid/agentic";

const sched = createWeeklyScheduler({
  coreUrl: "https://sauron.example.com",
  adminKey: process.env.SAURON_ADMIN_KEY!,
  tenantId: "acme_corp",
  circuitsDir: "/opt/sauron/zkp/circuits/build",
  // The two callbacks below are the customer's integration point — they
  // pull receipts from the customer's own datastore + compute the merkle
  // bundle. The scheduler does NOT assume access to the customer DB.
  receiptsProvider: async ({ start, end }) => fetchReceiptsBetween(start, end),
  merkleProofProvider: async (receipts) => buildMerkleBundle(receipts),
  onSubmit: (id, r) => log.info({ id, ...r }),
  onSkip:   (id, why) => log.info({ id, skipped: why }),
  onError:  (id, e) => log.error({ id, err: e.message }),
});
sched.start();
```

`submitWeeklyStats(opts)` is the one-shot variant for ad-hoc backfills.

## Audit anchoring

After a successful insert, the server writes a row into
`agent_action_receipts` with:

- `action_hash = SHA256("stats_submission:" + merkle_root + ":" + metric_id)`
- `receipt_id  = "stats_" + first16(action_hash)`
- `agent_id    = "__stats__:" + tenant_id [+ ":" + agent_id]`
- `policy_version = "stats-v1"`
- `status      = "stats_submitted"`

The synthetic `action_hash` lives in a distinct namespace
(`stats_submission:` prefix) so it can never collide with a real
agent action hash. The existing
`core/src/agent_action_anchor.rs::anchor_pending_actions` batcher
picks the row up on its next pass and rolls the stats submission into
the next OTS + Solana attestation. This means an auditor with a single
`customer_stats` row can:

1. Recompute `action_hash` from `merkle_root` + `metric_id`.
2. Look it up in `agent_action_receipts`.
3. Walk `/admin/anchor/agent-actions/proof?receipt_id=…` to the batch root.
4. Confirm the batch root on Bitcoin via OTS and on Solana via the memo
   signature.

So tampering with `customer_stats` post-anchor would also require
forging Bitcoin and Solana attestations — not a realistic adversary.

## What we don't cover yet

- **Percentile metrics in ZK.** Need a permutation-argument circuit.
  Tracked in `zkp/ceremony/circuits-list.json` as a follow-up.
- **Distinct-cardinality metrics in ZK.** Same — needs a sorted-
  uniqueness gadget.
- **Arity above four.** The current circuit is deliberately fixed at four and
  proves complete coverage only for that fixed tree. A transparent zkVM/STARK
  or a reviewed recursive construction is the migration path; independently
  proving chunks does not establish completeness for the union by itself.
- **Real trusted setup ceremony.** Sprint 4 already labelled the DEV
  keys as `*.dev.zkey` / `*.dev.vkey.json`. Production deployments
  MUST swap them; the file naming convention prevents a silent drop-in.
- **DP publishing endpoint.** Sprint 8 introduces `cohort.rs` and
  `publish.rs`; this sprint only stores per-tenant raw claims.
- **Cohort definitions (vendor=Gemini, sector=banking).** Sprint 8.
- **Dashboard UI for cohort views.** Sprint 9.

## File map

```
agentic/src/stats/
  metric-catalog.ts          — 10 metrics + sensitivity + provable flag
  local-aggregate.ts         — LocalAggregator (compute / computeAll)
  integrity-proof.ts         — StatsProver, witness layout, NotProvableError

agentic/src/scheduler.ts     — WeeklyStatsScheduler + submitWeeklyStats

zkp/circuits/StatsHonestComputation.circom
zkp/circuits/test/stats.test.js
zkp/sdk/src/action-log.ts    — proveStatsHonest helper (new)

core/src/aggregation/
  mod.rs       — re-exports
  submission.rs — StatsSubmission / StatsSubmitResponse / CohortRow
  verify.rs    — verify_stats_submission + AggError
  store.rs     — upsert + list + anchor + synthetic_action_hash
  handlers.rs  — POST /v1/stats/submit, GET /v1/stats/cohort

core/src/db.rs              — customer_stats table (sqlite)
migrations/postgres/0005_customer_stats.sql

docs/stats-submission.md     — this file
```

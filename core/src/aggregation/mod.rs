//! Customer-side stat aggregation + ZK integrity (Sprint 7).
//!
//! Wire flow:
//!
//! ```text
//!   SDK (agentic)                      Server (this module)
//!   ───────────────────                ──────────────────────
//!   commit N receipts                  /v1/stats/submit
//!   compute 10 metrics                 │
//!   prove StatsHonestComputation       ├─► verify::verify_stats_submission
//!   POST {stat, proof, root, ...} ────►│      • payload sanity
//!                                      │      • metric_id ∈ provable set
//!                                      │      • public_inputs ↔ body bind
//!                                      │      • snarkjs subprocess
//!                                      ├─► store::upsert_submission
//!                                      │      • idempotent INSERT
//!                                      ├─► store::anchor_submission
//!                                      │      • synthetic action_hash
//!                                      │      • row in agent_action_receipts
//!                                      └─► returns {stored, latency_ms,
//!                                                  anchored_action_hash}
//! ```
//!
//! Documentation: `docs/stats-submission.md`.

pub mod cohorts;
pub mod handlers;
pub mod he_aggregator;
pub mod he_store;
pub mod publish;
pub mod store;
pub mod submission;
pub mod verify;

pub use cohorts::{CohortDefinition, CohortError, CohortStore, DEFAULT_CYCLE_SECONDS};
pub use publish::{
    publish_cohort, publish_cohort_with_ledger, PrivacyNotice, PublishError, PublishedCohort,
    PublishedMetric, QUARTILE_SENSITIVITY,
};
pub use store::{
    anchor_submission, get_one, list_cohort, list_for_cohort, synthetic_action_hash,
    upsert_submission,
};
pub use submission::{CohortRow, StatsSubmission, StatsSubmitResponse};
pub use verify::{verify_stats_submission, AggError, PROVABLE_METRICS};

pub use he_aggregator::HeAggregator;
pub use he_store::{get_he_aggregation, upsert_he_aggregation, HeAggregationRow, HeStoreError};

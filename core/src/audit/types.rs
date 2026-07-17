//! Domain types for the audit report module (Sprint 19-20).
//!
//! Each section of an audit report attaches a typed `SectionEvidence`
//! enum so machine consumers can extract structured data without
//! reparsing free-text. Verdicts close each section either as
//! `Confirmed` (proof + anchors + policy all line up), `Partial` (some
//! evidence missing but the claim still holds in spirit) or
//! `Insufficient` (not enough data to conclude — the report flags the
//! gap explicitly rather than silently omitting it).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Typed evidence backing one section of an audit report.
///
/// Variants are flat (no nested enums) so a downstream tool can match
/// on `tag` without recursive parsing. Adding a new variant requires
/// a SIEM-rule update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum SectionEvidence {
    /// Spend-bound proof — claim is `spend_total ≤ budget` provable
    /// via the `ActionSumBound` circuit.
    SpendBound {
        /// Circuit identifier (e.g. `"ActionSumBound"`).
        circuit: String,
        /// Snarkjs-formatted public inputs (decimal strings).
        public_inputs: Vec<String>,
        /// Human-readable claim line ("spend ≤ 1000 USD").
        claim: String,
    },
    /// Tool allowlist enforced by policy DSL. The audit log delivers
    /// the count of attempted out-of-allowlist actions.
    ToolAllowlist {
        /// Allowlist as declared in the active policy binding.
        allowlist: Vec<String>,
        /// Count of denial events whose check involves the allowlist.
        attempted_violations: u32,
    },
    /// Time-window compliance — actions must fall within `[start, end]`.
    TimeWindow {
        /// RFC3339 / ISO 8601 window start.
        window_start: String,
        /// RFC3339 / ISO 8601 window end.
        window_end: String,
        /// Count of denial events tagged with a time-window check.
        violations: u32,
    },
    /// Anchor evidence inline at the section level (mirrors
    /// [`AnchorEvidence`] but per-section).
    AnchorChain {
        /// Latest BTC merkle root in the period (hex).
        btc_root: Option<String>,
        /// Bitcoin block height at confirmation. Best-effort —
        /// SauronID's anchor store records the OTS calendar but not
        /// always the final block height.
        btc_block: Option<u32>,
        /// Solana signature for the same period.
        solana_sig: Option<String>,
        /// Solana slot for the signature.
        solana_slot: Option<u64>,
    },
    /// Stats submission anchored by a ZK proof.
    StatsCommitment {
        /// Metric identifier (e.g. `"success_rate"`).
        metric_id: String,
        /// Claimed numeric value (decoded from fixed-point ×1000).
        value: f64,
        /// Number of records covered by the submission.
        n_records: u32,
        /// Verifying-key identifier (e.g. `"StatsHonestComputation.dev.vk@v0"`).
        vk_id: String,
    },
    /// Aggregate policy-evaluation outcome from `security_audit_log`.
    PolicyEvaluations {
        /// Total allowed actions in the period.
        allowed: u32,
        /// Total denied actions in the period.
        denied: u32,
        /// Per-check breakdown of denials.
        denial_breakdown: HashMap<String, u32>,
    },
}

/// Closed-state verdict for a single section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
pub enum SectionVerdict {
    /// All evidence aligns — the claim holds.
    Confirmed,
    /// Some evidence missing but the claim still holds in spirit.
    Partial {
        /// Free-text listing of what is missing.
        gaps: Vec<String>,
    },
    /// Not enough data — explicitly flagged rather than silently
    /// omitted.
    Insufficient {
        /// Why the verdict cannot be confirmed.
        reason: String,
    },
}

/// Bitcoin / Solana anchor evidence at the report level.
///
/// Bundled into [`crate::audit::report::AuditReport`] once so
/// downstream tooling can present a single "where did this land"
/// banner per report without scanning each section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorEvidence {
    /// Merkle root the anchors timestamp (hex).
    pub merkle_root: String,
    /// Base64-encoded OTS receipt blob. Absent for legacy mock
    /// anchors that predate the OTS upgrade.
    pub bitcoin_ots_receipt_b64: Option<String>,
    /// Block height at OTS upgrade. Operator-best-effort — see
    /// `core/src/bitcoin_anchor.rs` for the upgrade pipeline.
    pub bitcoin_block_height: Option<u32>,
    /// Solana memo-program signature for the same root.
    pub solana_signature: Option<String>,
    /// Solana slot at confirmation.
    pub solana_slot: Option<u64>,
}

/// High-level compliance summary attached to every report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceSummary {
    /// Policy ids evaluated during the period (deduplicated).
    pub policy_ids_evaluated: Vec<String>,
    /// Total actions (allowed + denied).
    pub total_actions: u32,
    /// Allowed actions in the period.
    pub allowed: u32,
    /// Denied actions in the period.
    pub denied: u32,
    /// `denied / total_actions`, clamped to `[0,1]`. Set to `0.0`
    /// when `total_actions == 0` so the wire shape never carries a
    /// NaN.
    pub policy_violation_rate: f64,
}

impl ComplianceSummary {
    /// Build a summary from raw allowed/denied counts; clamps the
    /// derived rate to a finite value.
    pub fn from_counts(policy_ids: Vec<String>, allowed: u32, denied: u32) -> Self {
        let total = allowed.saturating_add(denied);
        let rate = if total == 0 {
            0.0
        } else {
            (denied as f64) / (total as f64)
        };
        Self {
            policy_ids_evaluated: policy_ids,
            total_actions: total,
            allowed,
            denied,
            policy_violation_rate: rate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compliance_summary_zero_total_yields_zero_rate() {
        let s = ComplianceSummary::from_counts(vec![], 0, 0);
        assert_eq!(s.total_actions, 0);
        assert_eq!(s.policy_violation_rate, 0.0);
        assert!(s.policy_violation_rate.is_finite());
    }

    #[test]
    fn compliance_summary_half_denied_yields_half_rate() {
        let s = ComplianceSummary::from_counts(vec!["pol1".into()], 5, 5);
        assert_eq!(s.total_actions, 10);
        assert!((s.policy_violation_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn section_verdict_serializes_with_state_tag() {
        let v = SectionVerdict::Partial {
            gaps: vec!["missing OTS receipt".into()],
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"state\":\"Partial\""));
        assert!(s.contains("missing OTS receipt"));
    }

    #[test]
    fn section_evidence_round_trips_through_serde() {
        let e = SectionEvidence::StatsCommitment {
            metric_id: "success_rate".into(),
            value: 0.95,
            n_records: 100,
            vk_id: "StatsHonestComputation.dev.vk@v0".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: SectionEvidence = serde_json::from_str(&s).unwrap();
        match back {
            SectionEvidence::StatsCommitment {
                metric_id,
                n_records,
                ..
            } => {
                assert_eq!(metric_id, "success_rate");
                assert_eq!(n_records, 100);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}

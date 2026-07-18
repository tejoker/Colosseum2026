#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

pub const JOURNAL_PROTOCOL: &str = "sauron.transparent-proof.v1";
pub const STATS_PROGRAM_ID: &str = "sauron-stats-v1";
pub const ACTION_POLICY_PROGRAM_ID: &str = "sauron-action-policy-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransparentJournal {
    pub protocol: String,
    pub program_id: String,
    pub statement: TransparentStatement,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TransparentStatement {
    Stats {
        tenant_id: String,
        checkpoint_id: String,
        action_anchor_id: String,
        merkle_root: String,
        tree_size: u64,
        #[serde(default)]
        agent_id_or_none: Option<String>,
        metric_id: String,
        claimed_value: i64,
        period_start: i64,
        period_end: i64,
    },
    ActionPolicy {
        tenant_id: String,
        checkpoint_id: String,
        action_anchor_id: String,
        merkle_root: String,
        tree_size: u64,
        predicate_id: String,
        predicate_parameters_sha256: String,
    },
}

/// Exact preimage of `agent_action::action_hash`.  The guest serializes this
/// with the same fixed field order used by the core, then SHA-256 hashes it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentActionEnvelope {
    pub agent_id: String,
    pub human_key_image: String,
    pub action: String,
    pub resource: String,
    pub merchant_id: String,
    pub amount_minor: i64,
    pub currency: String,
    pub nonce: String,
    pub expires_at: i64,
    pub policy_hash: String,
    pub ajwt_jti: String,
}

/// All fields committed by `sauron.action-anchor-leaf.v2`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchoredReceiptV2 {
    pub tenant_id: String,
    pub receipt_id: String,
    pub action_hash: String,
    pub agent_id: String,
    pub ring_key_image_hex: String,
    pub policy_version: String,
    pub ajwt_jti: String,
    pub pop_jkt: String,
    pub status: String,
    pub signature: String,
    pub created_at: i64,
    pub ring_id: String,
    pub config_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrivateStatsRecord {
    pub envelope: AgentActionEnvelope,
    pub receipt: AnchoredReceiptV2,
}

/// Private input to the reviewed stats guest.  `claimed_value` is deliberately
/// absent: the guest computes it and publishes the result in its journal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatsProofInput {
    pub tenant_id: String,
    pub checkpoint_id: String,
    pub action_anchor_id: String,
    pub expected_merkle_root: String,
    #[serde(default)]
    pub agent_id_or_none: Option<String>,
    pub metric_id: String,
    pub period_start: i64,
    pub period_end: i64,
    pub records: Vec<PrivateStatsRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionPredicate {
    AllActionsIn {
        allowed_actions: Vec<String>,
    },
    TotalAmountAtMost {
        currency: String,
        maximum_minor: i64,
    },
    CountInRange {
        minimum: u64,
        maximum: u64,
    },
    NoAction {
        forbidden_action: String,
    },
    ContainsAction {
        required_action: String,
    },
    TimeWindow {
        not_before: i64,
        not_after: i64,
    },
}

impl ActionPredicate {
    pub fn id(&self) -> &'static str {
        match self {
            Self::AllActionsIn { .. } => "all_actions_in",
            Self::TotalAmountAtMost { .. } => "total_amount_at_most",
            Self::CountInRange { .. } => "count_in_range",
            Self::NoAction { .. } => "no_action",
            Self::ContainsAction { .. } => "contains_action",
            Self::TimeWindow { .. } => "time_window",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionPolicyProofInput {
    pub tenant_id: String,
    pub checkpoint_id: String,
    pub action_anchor_id: String,
    pub expected_merkle_root: String,
    #[serde(default)]
    pub agent_id_or_none: Option<String>,
    pub predicate: ActionPredicate,
    pub records: Vec<PrivateStatsRecord>,
}

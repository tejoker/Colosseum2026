//! Audit report struct + builder + canonical-form signing.
//!
//! The report is content-addressed: an HMAC-SHA256 over the canonical
//! JSON form of the (report_id, sections, anchors, zk_proofs, summary)
//! tuple. Operators may swap the placeholder HMAC for an Ed25519
//! signature backed by their key-infra at deploy time — the wire
//! shape is unchanged.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::types::{AnchorEvidence, ComplianceSummary, SectionEvidence, SectionVerdict};

type HmacSha256 = Hmac<Sha256>;

/// Single section of an audit report — one human-readable claim
/// backed by typed evidence + a verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    /// Heading shown in the rendered report (e.g. "Spend Budget Compliance").
    pub heading: String,
    /// Human-readable statement of the claim.
    pub statement: String,
    /// Typed evidence enum — see [`SectionEvidence`].
    pub evidence: SectionEvidence,
    /// Verdict closing the section.
    pub verdict: SectionVerdict,
}

/// ZK proof attached at the report level — typically a stats
/// submission's proof, or a future [Action]SumBound proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachedProof {
    /// Circuit identifier (e.g. `"StatsHonestComputation"`).
    pub circuit: String,
    /// Snarkjs-formatted public inputs (decimal strings).
    pub public_inputs: Vec<String>,
    /// Base64-encoded proof bytes.
    pub proof_b64: String,
    /// Verifying-key identifier (file basename minus `.json`).
    pub vk_id: String,
}

/// Top-level audit report — the customer compliance officer's
/// single artifact for a periodic review.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReport {
    /// 32-char hex UUID — generated server-side at build time.
    pub report_id: String,
    /// Tenant the report covers.
    pub tenant_id: String,
    /// Scope of the report: which agents in this tenant.
    pub agent_ids: Vec<String>,
    /// Unix epoch seconds: inclusive lower bound of the period.
    pub period_start: i64,
    /// Unix epoch seconds: inclusive upper bound of the period.
    pub period_end: i64,
    /// Unix epoch seconds: when the report was built.
    pub generated_at: i64,
    /// Merkle root anchoring the receipts in this report (hex). When
    /// no anchor exists yet for the period this is the empty string;
    /// downstream tooling should treat that as "anchor pending".
    pub merkle_root: String,
    /// Ordered sections — built deterministically by
    /// [`super::builder::build_audit_report`] so two runs on the
    /// same DB state yield byte-equal output (modulo `generated_at`).
    pub sections: Vec<AuditSection>,
    /// Report-level anchor evidence.
    pub anchors: AnchorEvidence,
    /// Attached ZK proofs (Sprint 7 stats submissions in the period).
    pub zk_proofs: Vec<AttachedProof>,
    /// Receipt count in the period.
    pub raw_receipts_count: u32,
    /// High-level compliance summary.
    pub policy_compliance_summary: ComplianceSummary,
}

impl AuditReport {
    /// Canonical-form bytes used as the HMAC input. Excludes
    /// `generated_at` so two reports built moments apart over the
    /// same DB state collide on signature — the operator can use the
    /// signature as a content-address.
    ///
    /// Uses `serde_json::to_vec` (lexicographic — Rust serde_json is
    /// stable for `serde_json::Value`). For struct fields the order
    /// follows source-order, which is fixed by the type definition.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Build a JSON value with `generated_at` zeroed for stability.
        #[derive(Serialize)]
        struct Canon<'a> {
            report_id: &'a str,
            tenant_id: &'a str,
            agent_ids: &'a [String],
            period_start: i64,
            period_end: i64,
            merkle_root: &'a str,
            sections: &'a [AuditSection],
            anchors: &'a AnchorEvidence,
            zk_proofs: &'a [AttachedProof],
            raw_receipts_count: u32,
            policy_compliance_summary: &'a ComplianceSummary,
        }
        let c = Canon {
            report_id: &self.report_id,
            tenant_id: &self.tenant_id,
            agent_ids: &self.agent_ids,
            period_start: self.period_start,
            period_end: self.period_end,
            merkle_root: &self.merkle_root,
            sections: &self.sections,
            anchors: &self.anchors,
            zk_proofs: &self.zk_proofs,
            raw_receipts_count: self.raw_receipts_count,
            policy_compliance_summary: &self.policy_compliance_summary,
        };
        serde_json::to_vec(&c).unwrap_or_default()
    }
}

/// HMAC-SHA256 over the report's canonical form using an HKDF-separated
/// audit-report key. Hex-encoded. This is an internal integrity MAC, not a
/// publicly verifiable signature; external chain-of-custody exports must be
/// signed by the operator's asymmetric KMS/threshold-signing workflow.
pub fn sign_report(report: &AuditReport, key: &[u8]) -> String {
    let separated = crate::crypto_protocol::derive_subkey(key, "audit-report-hmac-v1");
    let mut mac = HmacSha256::new_from_slice(&separated).expect("HMAC key length");
    mac.update(&report.canonical_bytes());
    let tag = mac.finalize().into_bytes();
    hex::encode(tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty_report() -> AuditReport {
        AuditReport {
            report_id: "deadbeef".repeat(4),
            tenant_id: "tnt".into(),
            agent_ids: vec![],
            period_start: 0,
            period_end: 60,
            generated_at: 100,
            merkle_root: String::new(),
            sections: vec![],
            anchors: AnchorEvidence {
                merkle_root: String::new(),
                bitcoin_ots_receipt_b64: None,
                bitcoin_block_height: None,
                solana_signature: None,
                solana_slot: None,
            },
            zk_proofs: vec![],
            raw_receipts_count: 0,
            policy_compliance_summary: ComplianceSummary::from_counts(vec![], 0, 0),
        }
    }

    #[test]
    fn build_empty_report_round_trips_through_serde() {
        let r = empty_report();
        let s = serde_json::to_string(&r).unwrap();
        let back: AuditReport = serde_json::from_str(&s).unwrap();
        assert_eq!(back.report_id, r.report_id);
        assert_eq!(back.tenant_id, "tnt");
        assert_eq!(back.sections.len(), 0);
        assert_eq!(back.zk_proofs.len(), 0);
    }

    #[test]
    fn build_with_sections_carries_typed_evidence_through_round_trip() {
        let mut r = empty_report();
        r.sections.push(AuditSection {
            heading: "Tool Allowlist".into(),
            statement: "Agent stayed within declared allowlist".into(),
            evidence: SectionEvidence::ToolAllowlist {
                allowlist: vec!["read".into(), "write".into()],
                attempted_violations: 0,
            },
            verdict: SectionVerdict::Confirmed,
        });
        r.sections.push(AuditSection {
            heading: "Policy Evaluations".into(),
            statement: "Allowed=4, denied=1".into(),
            evidence: SectionEvidence::PolicyEvaluations {
                allowed: 4,
                denied: 1,
                denial_breakdown: HashMap::from([("allowlist".to_string(), 1)]),
            },
            verdict: SectionVerdict::Partial {
                gaps: vec!["1 denial unreviewed".into()],
            },
        });
        let s = serde_json::to_string(&r).unwrap();
        let back: AuditReport = serde_json::from_str(&s).unwrap();
        assert_eq!(back.sections.len(), 2);
        match &back.sections[0].evidence {
            SectionEvidence::ToolAllowlist { allowlist, .. } => {
                assert_eq!(allowlist.len(), 2);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
        match &back.sections[1].verdict {
            SectionVerdict::Partial { gaps } => assert_eq!(gaps.len(), 1),
            other => panic!("unexpected verdict: {other:?}"),
        }
    }

    #[test]
    fn signature_is_deterministic_across_runs_and_ignores_generated_at() {
        let mut r = empty_report();
        let s1 = sign_report(&r, b"k1");
        r.generated_at = 999_999;
        let s2 = sign_report(&r, b"k1");
        assert_eq!(s1, s2, "generated_at must be excluded from canonical form");
        // Different key → different signature.
        let s3 = sign_report(&r, b"k2");
        assert_ne!(s1, s3);
        // Tag is 32 bytes → 64 hex chars.
        assert_eq!(s1.len(), 64);
    }
}

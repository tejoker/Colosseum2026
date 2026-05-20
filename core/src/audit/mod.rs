//! Sprint 19-20 — periodic ZK audit report module.
//!
//! Customer-side compliance officers generate a periodic audit report,
//! a single signed JSON artefact bundling:
//!
//! - Receipts in the period (count + merkle root).
//! - The Bitcoin OTS + Solana memo anchors that timestamp that root.
//! - Stats submissions with their ZK proofs (Sprint 7).
//! - Policy evaluation breakdown drawn from `security_audit_log`.
//! - Section-level verdicts (`Confirmed` / `Partial` / `Insufficient`).
//!
//! The report is content-addressed via HMAC-SHA256 over its canonical
//! JSON form, persisted in `audit_reports`, and surfaced via
//! `POST /v1/audit/reports`, `GET /v1/audit/reports/:id`,
//! `GET /v1/audit/reports`.
//!
//! See `report.rs` for the wire types, `builder.rs` for the assembly
//! algorithm, and `handlers.rs` for the HTTP surface.

pub mod builder;
pub mod handlers;
pub mod report;
pub mod store;
pub mod types;

pub use builder::{build_audit_report, AuditError, BuildRequest};
pub use report::{sign_report, AttachedProof, AuditReport, AuditSection};
pub use store::{ensure_audit_reports_schema, get_report, list_reports, store_report};
pub use types::{AnchorEvidence, ComplianceSummary, SectionEvidence, SectionVerdict};

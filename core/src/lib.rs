pub mod admin;
pub mod agent;
pub mod agent_action;
pub mod agent_action_anchor;
pub mod agent_checksum;
pub mod aggregation;
pub mod ajwt_support;
pub mod attestation;
pub mod audit;
/// Back-compat alias: the legacy `attestation_cbor` flat-file module lives at
/// `attestation::cbor` since the Sprint 6 module-layout refactor. Existing
/// integration tests import `sauron_core::attestation_cbor::*` — this
/// re-export preserves that path without forcing every test to update its
/// `use` lines.
pub use attestation::cbor as attestation_cbor;
pub mod bitcoin_anchor;
pub mod compliance;
pub mod db;
pub mod dp;
pub mod error;
pub mod feature_flags;
pub mod he;
pub mod identity;
pub mod issuer_runtime;
pub mod merkle;
pub mod middleware;
pub mod oprf;
pub mod policy;
pub mod repository;
pub mod ring;
pub mod ring_pseudonym;
pub mod rings;
pub mod risk;
pub mod routes;
pub mod runtime_mode;
pub mod secret_provider;
pub mod sites;
pub mod solana_anchor;
pub mod state;
pub mod tenancy;
pub mod usage;
pub mod zk_verifier;

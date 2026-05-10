//! Deployment-profile feature flags.
//!
//! SauronID's core deliverable is **AI agent binding** (per-agent identity, leash,
//! per-call signature, replay protection). The repo also carries optional features
//! inherited from the prior banking-identity positioning: bank KYC ingest, end-user
//! KYC consent flow, ZKP issuer integration, and compliance screening. These are
//! still useful for some deployments but are NOT required for the agent-binding
//! product surface.
//!
//! Each optional surface is gated by an env flag. **Default: enabled** for
//! backwards compatibility — existing tests and deployments keep working without
//! any env changes. **Recommended for new AI-agent deployments: disable them all
//! and ship a focused agent-binding stack.**
//!
//! | Surface          | Disable env                       | Effect when disabled                                |
//! |------------------|-----------------------------------|------------------------------------------------------|
//! | Bank KYC ingest  | `SAURON_DISABLE_BANK_KYC=1`       | `/bank/register`, `/register/bank` return 503        |
//! | End-user KYC     | `SAURON_DISABLE_USER_KYC=1`       | `/kyc/request`, `/kyc/consent`, `/kyc/retrieve` 503  |
//! | ZKP issuer       | `SAURON_DISABLE_ZKP=1`            | `/zkp/proof_material`, `/user/credential`,           |
//! |                  |                                   | `/agent/vc/issue` return 503; issuer URL not contacted|
//! | Compliance       | `SAURON_DISABLE_COMPLIANCE=1`     | jurisdiction + sanctions + PEP gates become no-ops   |
//!
//! Use `is_disabled("FOO")` for tri-state parsing (`1`/`true`/`yes` => disabled).

fn is_disabled(env_var: &str) -> bool {
    match std::env::var(env_var).ok() {
        Some(v) => {
            let low = v.to_ascii_lowercase();
            v == "1" || low == "true" || low == "yes"
        }
        None => false,
    }
}

pub fn bank_kyc_enabled() -> bool {
    !is_disabled("SAURON_DISABLE_BANK_KYC")
}

pub fn user_kyc_enabled() -> bool {
    !is_disabled("SAURON_DISABLE_USER_KYC")
}

pub fn zkp_issuer_enabled() -> bool {
    !is_disabled("SAURON_DISABLE_ZKP")
}

pub fn compliance_enabled() -> bool {
    !is_disabled("SAURON_DISABLE_COMPLIANCE")
}

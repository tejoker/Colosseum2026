//! Sprint 1 — advisory → enforce: validate that the `SAURON_REQUIRE_*`
//! defaults flip with `ENV` and that production refuses to start with an
//! explicit enforcement disable.
//!
//! Env vars are process-global so every test acquires a shared mutex
//! before touching them and an `EnvScope` restores the prior value on
//! drop. The 4 scenarios cover:
//!   1. Dev mode default: `require_or_default` returns the dev default.
//!   2. Prod mode default: same call returns the prod default.
//!   3. Explicit `SAURON_REQUIRE_CALL_SIG=1` in dev → enforce wins.
//!   4. Explicit `SAURON_REQUIRE_CALL_SIG=0` in prod → safety assertion
//!      refuses to start (no `SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD`).

use std::sync::{Mutex, OnceLock};

use sauron_core::runtime_mode::{
    assert_production_enforcement_safe, policy_enforcement_mode, require_or_default,
    PolicyEnforcementMode,
};

/// Global lock — tests in this file mutate process env, so they MUST NOT
/// run concurrently. The lock is module-private (`Mutex<()>`) and acquired
/// by every test before any env mutation.
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// RAII guard — `set` / `unset` an env var for the duration of a scope
/// and put the prior value back on drop. Built locally to avoid a new
/// dev-dep on `temp-env` (no new Cargo deps per the sprint constraint).
struct EnvScope {
    pairs: Vec<(&'static str, Option<String>)>,
}

impl EnvScope {
    fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    fn set(mut self, key: &'static str, value: &str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::set_var(key, value);
        self.pairs.push((key, prev));
        self
    }

    fn unset(mut self, key: &'static str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::remove_var(key);
        self.pairs.push((key, prev));
        self
    }
}

impl Drop for EnvScope {
    fn drop(&mut self) {
        for (key, prev) in self.pairs.drain(..) {
            match prev {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

#[test]
fn dev_default_is_advisory() {
    let _g = env_lock().lock().unwrap();
    let _scope = EnvScope::new()
        .set("ENV", "development")
        .unset("SAURON_ENV")
        .unset("SAURON_REQUIRE_CALL_SIG")
        .unset("SAURON_REQUIRE_AGENT_TYPE")
        .unset("SAURON_POLICY_ENFORCEMENT_MODE");

    // require_or_default → returns the dev default in development.
    assert!(
        !require_or_default("SAURON_REQUIRE_CALL_SIG", false, true),
        "dev default for SAURON_REQUIRE_CALL_SIG must be advisory (false)",
    );
    assert!(
        !require_or_default("SAURON_REQUIRE_AGENT_TYPE", false, true),
        "dev default for SAURON_REQUIRE_AGENT_TYPE must be advisory (false)",
    );
    assert_eq!(
        policy_enforcement_mode(),
        PolicyEnforcementMode::Advisory,
        "policy enforcement default in dev must be Advisory",
    );
}

#[test]
fn prod_default_is_enforce() {
    let _g = env_lock().lock().unwrap();
    let _scope = EnvScope::new()
        .set("ENV", "production")
        .unset("SAURON_ENV")
        .unset("SAURON_REQUIRE_CALL_SIG")
        .unset("SAURON_REQUIRE_AGENT_TYPE")
        .unset("SAURON_POLICY_ENFORCEMENT_MODE");

    assert!(
        require_or_default("SAURON_REQUIRE_CALL_SIG", false, true),
        "prod default for SAURON_REQUIRE_CALL_SIG must be enforce (true)",
    );
    assert!(
        require_or_default("SAURON_REQUIRE_AGENT_TYPE", false, true),
        "prod default for SAURON_REQUIRE_AGENT_TYPE must be enforce (true)",
    );
    assert_eq!(
        policy_enforcement_mode(),
        PolicyEnforcementMode::Enforce,
        "policy enforcement default in prod must be Enforce",
    );
}

#[test]
fn explicit_enforce_overrides_dev_default() {
    let _g = env_lock().lock().unwrap();
    let _scope = EnvScope::new()
        .set("ENV", "development")
        .unset("SAURON_ENV")
        .set("SAURON_REQUIRE_CALL_SIG", "1")
        .set("SAURON_REQUIRE_AGENT_TYPE", "yes")
        .set("SAURON_POLICY_ENFORCEMENT_MODE", "enforce");

    assert!(
        require_or_default("SAURON_REQUIRE_CALL_SIG", false, true),
        "explicit =1 in dev must enforce",
    );
    assert!(
        require_or_default("SAURON_REQUIRE_AGENT_TYPE", false, true),
        "explicit =yes in dev must enforce",
    );
    assert_eq!(
        policy_enforcement_mode(),
        PolicyEnforcementMode::Enforce,
        "explicit enforce in dev must override Advisory default",
    );
}

#[test]
fn prod_refuses_start_with_explicit_disable() {
    let _g = env_lock().lock().unwrap();

    // Case A: explicit SAURON_REQUIRE_CALL_SIG=0 in prod refuses.
    {
        let _scope = EnvScope::new()
            .set("ENV", "production")
            .unset("SAURON_ENV")
            .set("SAURON_REQUIRE_CALL_SIG", "0")
            .unset("SAURON_REQUIRE_AGENT_TYPE")
            .unset("SAURON_POLICY_ENFORCEMENT_MODE")
            .unset("SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD");
        let err = assert_production_enforcement_safe()
            .expect_err("prod must refuse with REQUIRE_CALL_SIG=0");
        assert!(
            err.contains("SAURON_REQUIRE_CALL_SIG"),
            "error must name the offending var: {err}",
        );
    }

    // Case B: explicit SAURON_POLICY_ENFORCEMENT_MODE=off in prod refuses.
    {
        let _scope = EnvScope::new()
            .set("ENV", "production")
            .unset("SAURON_ENV")
            .unset("SAURON_REQUIRE_CALL_SIG")
            .unset("SAURON_REQUIRE_AGENT_TYPE")
            .set("SAURON_POLICY_ENFORCEMENT_MODE", "off")
            .unset("SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD");
        let err = assert_production_enforcement_safe()
            .expect_err("prod must refuse with POLICY_ENFORCEMENT_MODE=off");
        assert!(
            err.contains("SAURON_POLICY_ENFORCEMENT_MODE"),
            "error must name the offending var: {err}",
        );
    }

    // Case C: unsafe override unblocks (operator opt-in for migrations).
    {
        let _scope = EnvScope::new()
            .set("ENV", "production")
            .unset("SAURON_ENV")
            .set("SAURON_REQUIRE_CALL_SIG", "0")
            .unset("SAURON_REQUIRE_AGENT_TYPE")
            .unset("SAURON_POLICY_ENFORCEMENT_MODE")
            .set("SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD", "1");
        assert!(
            assert_production_enforcement_safe().is_ok(),
            "unsafe override must let prod start with explicit disable"
        );
    }
}

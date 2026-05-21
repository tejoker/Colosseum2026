//! Process-wide runtime mode (development vs production-like). Kept dependency-free so
//! compliance, risk, and DB layers can consult it without import cycles with `state`.
//!
//! Sprint 1 (advisory → enforce) added [`require_or_default`] so call sites that
//! gate behaviour on a `SAURON_REQUIRE_*` env-var share a single fail-closed-in-prod
//! contract instead of each re-implementing the truthy parser.

pub fn runtime_environment() -> String {
    std::env::var("ENV")
        .or_else(|_| std::env::var("SAURON_ENV"))
        .unwrap_or_else(|_| "production".to_string())
        .to_ascii_lowercase()
}

pub fn is_development_runtime() -> bool {
    matches!(
        runtime_environment().as_str(),
        "development" | "dev" | "local"
    )
}

/// Parse a truthy env var (`1` / `true` / `yes`, case-insensitive). Returns
/// `Some(true)` / `Some(false)` when the value is set to any recognised
/// truthy/falsy string, `None` when the var is absent or empty.
pub fn parse_truthy(value: &str) -> Option<bool> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Resolve a `SAURON_REQUIRE_*`-style flag with environment-aware defaults.
///
/// Contract:
/// - If the env var is *explicitly set* to a recognised truthy/falsy value
///   (`1`/`true`/`yes` vs `0`/`false`/`no`) the explicit value wins.
/// - If the env var is unset (or set to an unparseable string) the default
///   depends on runtime: `prod_default` in production-like runtimes,
///   `dev_default` in development.
///
/// Sprint 1 deliverable #1: production fails-closed by default; advisory
/// mode is reserved for `ENV=development`/`SAURON_ENV=dev|local`.
pub fn require_or_default(env_var: &str, dev_default: bool, prod_default: bool) -> bool {
    if let Ok(raw) = std::env::var(env_var) {
        if let Some(parsed) = parse_truthy(&raw) {
            return parsed;
        }
    }
    if is_development_runtime() {
        dev_default
    } else {
        prod_default
    }
}

/// Policy enforcement mode. Drives [`policy_enforcement_mode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEnforcementMode {
    /// Server-side policy denials short-circuit action endpoints with 403.
    Enforce,
    /// Server logs the deny but still allows the action to complete. Dev only.
    Advisory,
    /// Server skips policy evaluation entirely (explicit opt-out, never default).
    Off,
}

impl PolicyEnforcementMode {
    /// Stable string form for audit logs and HTTP health payloads.
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyEnforcementMode::Enforce => "enforce",
            PolicyEnforcementMode::Advisory => "advisory",
            PolicyEnforcementMode::Off => "off",
        }
    }
}

/// Resolve `SAURON_POLICY_ENFORCEMENT_MODE`. In production the default is
/// `enforce`; in development the default is `advisory`. `off` is only
/// reachable via the explicit `SAURON_POLICY_ENFORCEMENT_MODE=off` opt-out.
pub fn policy_enforcement_mode() -> PolicyEnforcementMode {
    match std::env::var("SAURON_POLICY_ENFORCEMENT_MODE")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("enforce") => PolicyEnforcementMode::Enforce,
        Some("advisory") => PolicyEnforcementMode::Advisory,
        Some("off") => PolicyEnforcementMode::Off,
        Some(other) if !other.is_empty() => {
            tracing::warn!(
                target: "sauron::runtime_mode",
                value = %other,
                "SAURON_POLICY_ENFORCEMENT_MODE not in {{enforce,advisory,off}} — using runtime default"
            );
            if is_development_runtime() {
                PolicyEnforcementMode::Advisory
            } else {
                PolicyEnforcementMode::Enforce
            }
        }
        _ => {
            if is_development_runtime() {
                PolicyEnforcementMode::Advisory
            } else {
                PolicyEnforcementMode::Enforce
            }
        }
    }
}

/// Assert that the running configuration is safe before the server binds
/// its TCP socket. Refuses to start when `ENV=production` and a critical
/// enforcement gate has been explicitly disabled without the matching
/// unsafe override flag. Called from `main`.
///
/// Returns `Err(reason)` for the caller to surface to the operator.
pub fn assert_production_enforcement_safe() -> Result<(), String> {
    if is_development_runtime() {
        return Ok(());
    }
    let unsafe_override = std::env::var("SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD")
        .ok()
        .and_then(|v| parse_truthy(&v))
        .unwrap_or(false);
    if unsafe_override {
        tracing::warn!(
            target: "sauron::runtime_mode",
            "SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD=1 set — production may run advisory enforcement gates"
        );
        return Ok(());
    }
    // Critical require-flags: if any are explicitly disabled, refuse start.
    for var in ["SAURON_REQUIRE_CALL_SIG", "SAURON_REQUIRE_AGENT_TYPE"] {
        if let Ok(raw) = std::env::var(var) {
            if matches!(parse_truthy(&raw), Some(false)) {
                return Err(format!(
                    "production runtime refuses to start with {var}={raw} (set SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD=1 to override)"
                ));
            }
        }
    }
    if matches!(policy_enforcement_mode(), PolicyEnforcementMode::Off) {
        return Err(
            "production runtime refuses to start with SAURON_POLICY_ENFORCEMENT_MODE=off (set SAURON_UNSAFE_ALLOW_ADVISORY_IN_PROD=1 to override)".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test owns a single env var name to avoid cross-test bleed. We
    // restore the prior value (or unset) at scope exit.
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }
    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prev }
        }
        fn unset(key: &'static str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn parse_truthy_recognises_common_values() {
        assert_eq!(parse_truthy("1"), Some(true));
        assert_eq!(parse_truthy("TRUE"), Some(true));
        assert_eq!(parse_truthy("yes"), Some(true));
        assert_eq!(parse_truthy("0"), Some(false));
        assert_eq!(parse_truthy("no"), Some(false));
        assert_eq!(parse_truthy(""), None);
        assert_eq!(parse_truthy("maybe"), None);
    }
}

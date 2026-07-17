//! Shared building blocks for the policy DSL: newtypes, enums, errors, validators.
//!
//! These types are deliberately small and dependency-free at the API surface
//! (`String`/primitive-only public fields where practical) so they round-trip
//! cleanly through serde and remain stable across Sprint 2 invariant work.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::hash::Hash;
use std::str::FromStr;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Validated, non-negative USD budget. Construct via [`Budget::new`] which
/// rejects negative values; this is the only invariant.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Budget(pub f64);

impl Budget {
    /// Create a new budget. Returns `Err` if `amount < 0` or not finite.
    pub fn new(amount: f64) -> Result<Self, PolicyParseError> {
        if !amount.is_finite() || amount < 0.0 {
            return Err(PolicyParseError::SchemaViolation(format!(
                "budget must be a finite, non-negative number, got {amount}"
            )));
        }
        Ok(Budget(amount))
    }

    /// Underlying numeric value.
    pub fn value(&self) -> f64 {
        self.0
    }
}

/// Set-based allow list parameterised over hashable item type.
///
/// Thin wrapper over `HashSet<T>` to give the policy DSL a stable type name
/// in API surfaces (the runtime evaluator in Sprint 2 will take these by
/// reference).
#[derive(Debug, Clone)]
pub struct Allowlist<T: Eq + Hash>(pub HashSet<T>);

impl<T: Eq + Hash> Allowlist<T> {
    /// Empty allowlist (matches nothing).
    pub fn empty() -> Self {
        Allowlist(HashSet::new())
    }

    /// `true` if the item is on the allowlist.
    pub fn contains(&self, item: &T) -> bool {
        self.0.contains(item)
    }

    /// Insert a value. Returns `true` if newly inserted.
    pub fn insert(&mut self, item: T) -> bool {
        self.0.insert(item)
    }
}

impl<T: Eq + Hash> Default for Allowlist<T> {
    fn default() -> Self {
        Allowlist::empty()
    }
}

impl<T: Eq + Hash> FromIterator<T> for Allowlist<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Allowlist(iter.into_iter().collect())
    }
}

/// Canonical data-classification tags used by `binding.data_scope`.
///
/// The DSL accepts arbitrary string tags; this enum is the recommended
/// canonical set. Unknown tags surface as [`DataClassification::Custom`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    /// Publicly available data, no access restriction.
    Public,
    /// Data owned by the customer; agent may operate on it under contract.
    CustomerOwned,
    /// Personally Identifiable Information.
    Pii,
    /// Financial records (transactions, balances, ledgers).
    Financial,
    /// Restricted by regulation or contract — agents must not touch unless
    /// explicitly authorised.
    Restricted,
    /// Any other tag the operator defines.
    Custom(String),
}

impl DataClassification {
    /// Parse a free-form tag into the canonical enum (case-insensitive for
    /// the canonical set, otherwise wraps in `Custom`).
    pub fn from_tag(tag: &str) -> Self {
        match tag.to_ascii_lowercase().as_str() {
            "public" => DataClassification::Public,
            "customer_owned" => DataClassification::CustomerOwned,
            "pii" => DataClassification::Pii,
            "financial" | "financial_records" => DataClassification::Financial,
            "restricted" => DataClassification::Restricted,
            _ => DataClassification::Custom(tag.to_string()),
        }
    }
}

/// Error type returned by every fallible policy DSL operation.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyParseError {
    /// YAML lexer/parser failed (line/column included in the message).
    InvalidYaml(String),
    /// JSON lexer/parser failed (line/column included in the message).
    InvalidJson(String),
    /// Parsed structurally but violated a semantic rule.
    SchemaViolation(String),
    /// `version` field has a value this build doesn't understand.
    UnsupportedVersion(String),
}

impl fmt::Display for PolicyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyParseError::InvalidYaml(m) => write!(f, "invalid yaml: {m}"),
            PolicyParseError::InvalidJson(m) => write!(f, "invalid json: {m}"),
            PolicyParseError::SchemaViolation(m) => write!(f, "schema violation: {m}"),
            PolicyParseError::UnsupportedVersion(m) => write!(f, "unsupported policy version: {m}"),
        }
    }
}

impl Error for PolicyParseError {}

static HHMM_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?:[01]\d|2[0-3]):[0-5]\d$").expect("HHMM regex must compile"));

/// Validate a `HH:MM` 24-hour timestamp string.
///
/// Accepts `00:00` through `23:59`. Leading zeros are required (`9:00` is
/// rejected — use `09:00`).
pub fn validate_hhmm(s: &str) -> Result<(), PolicyParseError> {
    if HHMM_RE.is_match(s) {
        Ok(())
    } else {
        Err(PolicyParseError::SchemaViolation(format!(
            "invalid HH:MM time '{s}' (expected 24-hour with leading zeros, e.g. 09:00)"
        )))
    }
}

/// Validate an IANA timezone string by attempting to construct a
/// [`chrono_tz::Tz`] from it.
pub fn validate_iana_tz(tz: &str) -> Result<(), PolicyParseError> {
    chrono_tz::Tz::from_str(tz)
        .map(|_| ())
        .map_err(|e| PolicyParseError::SchemaViolation(format!("invalid IANA tz '{tz}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_rejects_negative_and_nan() {
        assert!(Budget::new(-1.0).is_err());
        assert!(Budget::new(f64::NAN).is_err());
        assert!(Budget::new(f64::INFINITY).is_err());
        assert_eq!(Budget::new(0.0).unwrap().value(), 0.0);
        assert_eq!(Budget::new(42.5).unwrap().value(), 42.5);
    }

    #[test]
    fn hhmm_accepts_valid_and_rejects_invalid() {
        for ok in ["00:00", "09:00", "12:34", "23:59"] {
            assert!(validate_hhmm(ok).is_ok(), "{ok} should parse");
        }
        for bad in ["9:00", "24:00", "12:60", "1234", "noon", ""] {
            assert!(validate_hhmm(bad).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn iana_tz_accepts_known_and_rejects_unknown() {
        assert!(validate_iana_tz("Europe/Paris").is_ok());
        assert!(validate_iana_tz("UTC").is_ok());
        assert!(validate_iana_tz("America/New_York").is_ok());
        assert!(validate_iana_tz("Europe/Wakanda").is_err());
        assert!(validate_iana_tz("").is_err());
    }

    #[test]
    fn classification_canonicalises_tags() {
        assert_eq!(
            DataClassification::from_tag("PUBLIC"),
            DataClassification::Public
        );
        assert_eq!(
            DataClassification::from_tag("financial_records"),
            DataClassification::Financial
        );
        match DataClassification::from_tag("trade_secret") {
            DataClassification::Custom(s) => assert_eq!(s, "trade_secret"),
            _ => panic!("expected Custom"),
        }
    }
}

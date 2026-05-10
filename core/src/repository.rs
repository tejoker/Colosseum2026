//! Storage-backend abstraction for SauronID.
//!
//! **Status:** Phase 3 in progress. The full Postgres swap is a multi-week task;
//! this module is the migration template. New code SHOULD use this repository
//! API; existing code continues to call rusqlite directly until ported.
//!
//! ## Backends
//!
//! - **`Sqlite` (default)** — wraps the existing `r2d2 + rusqlite` pool, no
//!   behaviour change. The single-node SQLite path remains operational.
//! - **`Postgres` (opt-in)** — sqlx `PgPool`, real connection pooling,
//!   replication-friendly. Activated by `SAURON_DB_BACKEND=postgres` plus
//!   `DATABASE_URL=postgres://…`. Only modules ported to the repository API
//!   honour this backend; ported list grows incrementally.
//!
//! ## Ported modules (Phase 3 progress)
//!
//! | Module                     | rusqlite | sqlx::Postgres | Notes                      |
//! |----------------------------|:--------:|:--------------:|----------------------------|
//! | `agent_call_nonces` (this) |    ✓     |       ✓        | Migration template.        |
//! | `ajwt_used_jtis`           |    ✓     |                | Pending.                    |
//! | `risk_rate_counters`       |    ✓     |                | Pending.                    |
//! | `agent_pop_challenges`     |    ✓     |                | Pending.                    |
//! | `consent_log`              |    ✓     |                | Pending. TOCTOU-fixed.      |
//! | `agent_payment_*`          |    ✓     |                | Pending. TOCTOU-fixed.      |
//! | `bank_attestation_nonces`  |    ✓     |                | Pending. TOCTOU-fixed.      |
//! | `credential_codes`         |    ✓     |                | Pending. TOCTOU-fixed.      |
//! | `agents`                   |    ✓     |                | Pending.                    |
//! | `users`                    |    ✓     |                | Pending.                    |
//! | `merkle_leaves`            |    ✓     |                | Pending.                    |
//! | `bitcoin_merkle_anchors`   |    ✓     |                | Pending.                    |
//! | `solana_merkle_anchors`    |    ✓     |                | Pending.                    |
//!
//! ## Why incremental
//!
//! 12 source files reference `rusqlite::` directly across ~80 call sites.
//! Atomic swap risks correctness regressions on the security-critical TOCTOU
//! patterns we just fixed. Incremental port lets us rerun the 9-scenario
//! invariant suite after each module migrates and catch regressions early.
//!
//! ## Pattern for porting a module
//!
//! 1. Add a function on `Repo` that takes the high-level intent
//!    (e.g. `claim_call_nonce(agent_id, nonce, exp)`).
//! 2. Implement it for both backends inside the same function — match on
//!    `&self.kind` and dispatch to either rusqlite or sqlx.
//! 3. Update callers from raw SQL to `state.repo.claim_call_nonce(...)`.
//! 4. Run `bash run-all.sh` (default + enforce mode).

use std::sync::Arc;

use crate::db::DbHandle;

#[derive(Clone)]
pub enum Repo {
    Sqlite(Arc<DbHandle>),
    Postgres(sqlx::PgPool),
}

#[derive(Debug)]
pub enum RepoError {
    Backend(String),
    Replay(String),
}

impl std::fmt::Display for RepoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepoError::Backend(s) => write!(f, "{s}"),
            RepoError::Replay(s) => write!(f, "{s}"),
        }
    }
}

impl Repo {
    /// Build a Repo from environment configuration.
    ///
    /// `SAURON_DB_BACKEND=postgres` selects the sqlx Postgres path and requires
    /// `DATABASE_URL`. Anything else (including unset) selects the existing
    /// SQLite path, preserving full backwards compatibility.
    pub async fn from_env(sqlite: Arc<DbHandle>) -> Result<Self, String> {
        let backend = std::env::var("SAURON_DB_BACKEND")
            .unwrap_or_else(|_| "sqlite".to_string())
            .to_ascii_lowercase();
        match backend.as_str() {
            "postgres" | "pg" | "postgresql" => {
                let url = std::env::var("DATABASE_URL")
                    .map_err(|_| "DATABASE_URL must be set when SAURON_DB_BACKEND=postgres".to_string())?;
                let pool = sqlx::postgres::PgPoolOptions::new()
                    .max_connections(
                        std::env::var("SAURON_PG_POOL_SIZE")
                            .ok()
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(16u32),
                    )
                    .connect(&url)
                    .await
                    .map_err(|e| format!("postgres connect: {e}"))?;
                tracing::info!(target: "sauron::repo", backend = "postgres", "repository pool ready");
                Ok(Repo::Postgres(pool))
            }
            _ => {
                tracing::info!(target: "sauron::repo", backend = "sqlite", "repository on legacy rusqlite path");
                Ok(Repo::Sqlite(sqlite))
            }
        }
    }

    pub fn is_postgres(&self) -> bool {
        matches!(self, Repo::Postgres(_))
    }

    // ─── agent_call_nonces ─────────────────────────────────────────────────
    //
    // Atomic single-use insert. Errors with `RepoError::Replay` when the same
    // (agent_id, nonce) pair has already been consumed — this is the security
    // property: a captured per-call signature cannot be replayed.

    pub async fn consume_call_nonce(
        &self,
        agent_id: &str,
        nonce: &str,
        exp: i64,
    ) -> Result<(), RepoError> {
        if nonce.is_empty() {
            return Err(RepoError::Backend("missing call nonce".into()));
        }
        if nonce.len() > 128 {
            return Err(RepoError::Backend("call nonce too long (max 128 chars)".into()));
        }
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute(
                    "INSERT INTO agent_call_nonces (agent_id, nonce, exp) VALUES (?1, ?2, ?3)",
                    rusqlite::params![agent_id, nonce, exp],
                )
                .map_err(|e| {
                    let s = e.to_string();
                    if s.contains("UNIQUE") || s.contains("PRIMARY KEY") {
                        RepoError::Replay("call nonce replay (already used)".into())
                    } else {
                        RepoError::Backend(s)
                    }
                })?;
                Ok(())
            }
            Repo::Postgres(pool) => {
                let result = sqlx::query(
                    "INSERT INTO agent_call_nonces (agent_id, nonce, exp) VALUES ($1, $2, $3)",
                )
                .bind(agent_id)
                .bind(nonce)
                .bind(exp)
                .execute(pool)
                .await;
                match result {
                    Ok(_) => Ok(()),
                    Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                        Err(RepoError::Replay("call nonce replay (already used)".into()))
                    }
                    Err(e) => Err(RepoError::Backend(format!("postgres insert call nonce: {e}"))),
                }
            }
        }
    }

    /// Background-GC sweep for `agent_call_nonces`. Returns rows removed.
    pub async fn prune_call_nonces(&self, now: i64) -> Result<u64, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                let n = conn
                    .execute("DELETE FROM agent_call_nonces WHERE exp < ?1", rusqlite::params![now])
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(n as u64)
            }
            Repo::Postgres(pool) => {
                let r = sqlx::query("DELETE FROM agent_call_nonces WHERE exp < $1")
                    .bind(now)
                    .execute(pool)
                    .await
                    .map_err(|e| RepoError::Backend(format!("postgres prune call nonces: {e}")))?;
                Ok(r.rows_affected())
            }
        }
    }
}

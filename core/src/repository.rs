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
//! | Module                     | rusqlite | sqlx::Postgres | Notes                                                  |
//! |----------------------------|:--------:|:--------------:|--------------------------------------------------------|
//! | `agent_call_nonces`        |    ✓     |       ✓        | Migration template. Serializable txn wrapper (M1).     |
//! | `ajwt_used_jtis`           |    ✓     |       ✓        | M1 ported. Serializable txn wrapper.                   |
//! | `risk_rate_counters`       |    ✓     |       ✓        | M1 ported. Serializable txn wrapper for inc + read.    |
//! | `agent_pop_challenges`     |    ✓     |       ✓        | M2 ported (shipped 2026-05-15). GC + take helpers.     |
//! | `bank_attestation_nonces`  |    ✓     |       ✓        | M2 ported. UNIQUE-key consume.                         |
//! | `consent_log`              |    ✓     |       ✓        | M2 ported. FOR UPDATE + RETURNING token consume.       |
//! | `agent_payment_*`          |    ✓     |       ✓        | M2 ported. FOR UPDATE + RETURNING authorize consume.   |
//! | `credential_codes`         |    ✓     |       ✓        | M3 ported. claim flag flip with TOCTOU guard.          |
//! | `agents`                   |    ✓     |       ✓        | M3 ported. lookup + insert + revoke.                   |
//! | `agent_checksum_*`         |    ✓     |       ✓        | M3 ported. checksum input + audit trail.               |
//! | `users`                    |    ✓     |       ✓        | M3 ported. upsert + registration lookup.               |
//! | `merkle_leaves`            |    ✓     |       ✓        | M3 ported. append-only commitment insert.              |
//! | `bitcoin_merkle_anchors`   |    ✓     |       ✓        | M4 ported. anchor receipt insert + lookup.             |
//! | `solana_merkle_anchors`    |    ✓     |       ✓        | M4 ported. anchor receipt insert + lookup.             |
//! | `agent_action_receipts`    |    ✓     |       ✓        | M4 ported. receipt existence check.                    |
//!
//! ## Serializable transactions (M1)
//!
//! TOCTOU-sensitive paths (single-use nonce consume, JTI claim, rate-window
//! increment-and-check) run under explicit serializable isolation:
//!
//! - **SQLite**: `BEGIN IMMEDIATE TRANSACTION` acquires the writer lock for the
//!   life of the transaction. Combined with `journal_mode = WAL` + `busy_timeout`
//!   this gives single-writer serializable semantics for the wrapped block.
//! - **Postgres**: `BEGIN ISOLATION LEVEL SERIALIZABLE` with `SQLSTATE 40001`
//!   (`serialization_failure`) retry — up to 3 attempts with exponential backoff
//!   (10ms, 40ms, 90ms). The outer caller never observes the retry.
//!
//! `INSERT … ON CONFLICT DO NOTHING / DO UPDATE` is atomic at any isolation
//! level (the conflict resolution is in-statement), so the helpers below use
//! `INSERT` row-count + uniqueness for replay detection. The serializable
//! wrapper is belt-and-braces: even if a future helper adds a `SELECT … WHERE
//! flag = 0` followed by `UPDATE`, it cannot be torn by a concurrent reader.
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

    // ─── txn_serializable ──────────────────────────────────────────────────
    //
    // Run an SQLite operation under `BEGIN IMMEDIATE TRANSACTION` (writer lock
    // for the life of the txn — single-writer serialisable semantics in WAL
    // mode). The closure receives the pooled connection; it MUST NOT spawn
    // sub-tasks that touch the DB pool (they would deadlock on the writer lock).
    //
    // For TOCTOU-sensitive single-statement operations (`INSERT … ON CONFLICT`)
    // the IMMEDIATE-TX wrapper is belt-and-braces — the statement is already
    // atomic. The wrapper matters when the closure reads-then-writes.
    pub fn txn_immediate_sqlite<F, T>(&self, f: F) -> Result<T, RepoError>
    where
        F: FnOnce(&rusqlite::Connection) -> Result<T, RepoError>,
    {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute_batch("BEGIN IMMEDIATE TRANSACTION;")
                    .map_err(|e| RepoError::Backend(format!("begin immediate: {e}")))?;
                let res = f(&conn);
                match res {
                    Ok(v) => {
                        conn.execute_batch("COMMIT;")
                            .map_err(|e| RepoError::Backend(format!("commit: {e}")))?;
                        Ok(v)
                    }
                    Err(e) => {
                        let _ = conn.execute_batch("ROLLBACK;");
                        Err(e)
                    }
                }
            }
            Repo::Postgres(_) => Err(RepoError::Backend(
                "txn_immediate_sqlite called on Postgres backend".into(),
            )),
        }
    }

    // Run a Postgres operation under `BEGIN ISOLATION LEVEL SERIALIZABLE`,
    // retrying on `SQLSTATE 40001` (serialisation_failure) up to 3 attempts
    // with exponential backoff (10 / 40 / 90 ms). Any other error aborts.
    //
    // The closure receives a mutable `sqlx::Transaction<Postgres>` and SHOULD
    // run all of its statements via that handle; sqlx returns `?` errors as
    // `sqlx::Error`. Callers map domain errors via the `mapper` arg so the
    // retry loop can tell a TOCTOU collision (Replay) from a transient
    // serialisation failure (retry) from a hard backend error (abort).
    pub async fn txn_serializable_pg<F, T>(&self, mut f: F) -> Result<T, RepoError>
    where
        for<'c> F: FnMut(
            &'c mut sqlx::Transaction<'static, sqlx::Postgres>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, RepoError>> + Send + 'c>,
        >,
    {
        let pool = match self {
            Repo::Postgres(p) => p.clone(),
            Repo::Sqlite(_) => {
                return Err(RepoError::Backend(
                    "txn_serializable_pg called on SQLite backend".into(),
                ));
            }
        };
        let mut last_err: Option<RepoError> = None;
        for attempt in 0..3u32 {
            let mut tx = pool
                .begin()
                .await
                .map_err(|e| RepoError::Backend(format!("postgres begin: {e}")))?;
            // Upgrade to SERIALIZABLE for this txn (Postgres default is READ COMMITTED).
            if let Err(e) = sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                .execute(&mut *tx)
                .await
            {
                let _ = tx.rollback().await;
                return Err(RepoError::Backend(format!(
                    "postgres set isolation: {e}"
                )));
            }
            let inner = f(&mut tx).await;
            match inner {
                Ok(val) => match tx.commit().await {
                    Ok(()) => return Ok(val),
                    Err(sqlx::Error::Database(db_err))
                        if db_err.code().as_deref() == Some("40001") =>
                    {
                        last_err = Some(RepoError::Backend(format!(
                            "serialisation_failure on commit (attempt {})",
                            attempt + 1
                        )));
                    }
                    Err(e) => {
                        return Err(RepoError::Backend(format!("postgres commit: {e}")));
                    }
                },
                Err(e) => {
                    // Roll back; only retry if the error came from SQLSTATE 40001.
                    let _ = tx.rollback().await;
                    let retryable = matches!(&e, RepoError::Backend(s) if s.contains("40001") || s.contains("serialization_failure"));
                    if !retryable {
                        return Err(e);
                    }
                    last_err = Some(e);
                }
            }
            // Backoff: 10ms, 40ms, 90ms — total <150ms across 3 attempts.
            let backoff_ms = 10u64 + (attempt as u64) * 30 + (attempt as u64) * (attempt as u64) * 10;
            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
        }
        Err(last_err.unwrap_or_else(|| {
            RepoError::Backend("serialisable retry exhausted with no error captured".into())
        }))
    }

    // ─── agent_call_nonces ─────────────────────────────────────────────────
    //
    // Atomic single-use insert under serializable isolation. Errors with
    // `RepoError::Replay` when the same (agent_id, nonce) pair has already
    // been consumed — this is the security property: a captured per-call
    // signature cannot be replayed.

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
            Repo::Sqlite(_) => {
                let agent_id = agent_id.to_string();
                let nonce = nonce.to_string();
                self.txn_immediate_sqlite(move |conn| {
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
                })
            }
            Repo::Postgres(_) => {
                let agent_id = agent_id.to_string();
                let nonce = nonce.to_string();
                self.txn_serializable_pg(move |tx| {
                    let agent_id = agent_id.clone();
                    let nonce = nonce.clone();
                    Box::pin(async move {
                        let result = sqlx::query(
                            "INSERT INTO agent_call_nonces (agent_id, nonce, exp) VALUES ($1, $2, $3)",
                        )
                        .bind(&agent_id)
                        .bind(&nonce)
                        .bind(exp)
                        .execute(&mut **tx)
                        .await;
                        match result {
                            Ok(_) => Ok(()),
                            Err(sqlx::Error::Database(db_err))
                                if db_err.is_unique_violation() =>
                            {
                                Err(RepoError::Replay(
                                    "call nonce replay (already used)".into(),
                                ))
                            }
                            Err(sqlx::Error::Database(db_err))
                                if db_err.code().as_deref() == Some("40001") =>
                            {
                                Err(RepoError::Backend("40001 serialization_failure".into()))
                            }
                            Err(e) => Err(RepoError::Backend(format!(
                                "postgres insert call nonce: {e}"
                            ))),
                        }
                    })
                })
                .await
            }
        }
    }

    // ─── ajwt_used_jtis ────────────────────────────────────────────────────
    //
    // Single-use JTI claim under serializable isolation. Atomic INSERT; unique
    // constraint on `jti` is the replay detector. The wrapper protects against
    // future read-then-write helpers (e.g. "claim if not used AND not expired").
    pub async fn consume_ajwt_jti(&self, jti: &str, exp: i64) -> Result<(), RepoError> {
        if jti.is_empty() {
            return Err(RepoError::Backend("missing jti".into()));
        }
        if jti.len() > 256 {
            return Err(RepoError::Backend("jti too long (max 256 chars)".into()));
        }
        match self {
            Repo::Sqlite(_) => {
                let jti = jti.to_string();
                self.txn_immediate_sqlite(move |conn| {
                    conn.execute(
                        "INSERT INTO ajwt_used_jtis (jti, exp) VALUES (?1, ?2)",
                        rusqlite::params![jti, exp],
                    )
                    .map_err(|e| {
                        let s = e.to_string();
                        if s.contains("UNIQUE") || s.contains("PRIMARY KEY") {
                            RepoError::Replay("A-JWT jti replay (token already used)".into())
                        } else {
                            RepoError::Backend(s)
                        }
                    })?;
                    Ok(())
                })
            }
            Repo::Postgres(_) => {
                let jti = jti.to_string();
                self.txn_serializable_pg(move |tx| {
                    let jti = jti.clone();
                    Box::pin(async move {
                        let result =
                            sqlx::query("INSERT INTO ajwt_used_jtis (jti, exp) VALUES ($1, $2)")
                                .bind(&jti)
                                .bind(exp)
                                .execute(&mut **tx)
                                .await;
                        match result {
                            Ok(_) => Ok(()),
                            Err(sqlx::Error::Database(db_err))
                                if db_err.is_unique_violation() =>
                            {
                                Err(RepoError::Replay(
                                    "A-JWT jti replay (token already used)".into(),
                                ))
                            }
                            Err(sqlx::Error::Database(db_err))
                                if db_err.code().as_deref() == Some("40001") =>
                            {
                                Err(RepoError::Backend("40001 serialization_failure".into()))
                            }
                            Err(e) => {
                                Err(RepoError::Backend(format!("postgres insert jti: {e}")))
                            }
                        }
                    })
                })
                .await
            }
        }
    }

    // ─── risk_rate_counters ────────────────────────────────────────────────
    //
    // Increment-and-check under serializable isolation. The sequence is
    // `INSERT … ON CONFLICT DO UPDATE SET cnt = cnt + 1 RETURNING cnt` —
    // atomic, so the post-increment count cannot be stale under any isolation
    // level. The serializable wrapper still pays for itself because the GC
    // delete that runs alongside the increment can race with concurrent
    // increments under READ COMMITTED, and a multi-tenant Postgres deployment
    // wants the strongest isolation for security-critical counters.
    //
    // Returns the post-increment count. Caller compares to `max_per_window`.
    pub async fn risk_increment(
        &self,
        bucket: &str,
        window_id: i64,
    ) -> Result<i64, RepoError> {
        if bucket.is_empty() || bucket.len() > 128 {
            return Err(RepoError::Backend("risk bucket invalid".into()));
        }
        match self {
            Repo::Sqlite(_) => {
                let bucket = bucket.to_string();
                self.txn_immediate_sqlite(move |conn| {
                    conn.execute(
                        "INSERT INTO risk_rate_counters (bucket, window_id, cnt) VALUES (?1, ?2, 1)
                         ON CONFLICT(bucket, window_id) DO UPDATE SET cnt = cnt + 1",
                        rusqlite::params![bucket, window_id],
                    )
                    .map_err(|e| RepoError::Backend(format!("risk insert: {e}")))?;
                    let cnt: i64 = conn
                        .query_row(
                            "SELECT cnt FROM risk_rate_counters WHERE bucket = ?1 AND window_id = ?2",
                            rusqlite::params![bucket, window_id],
                            |r| r.get(0),
                        )
                        .map_err(|e| RepoError::Backend(format!("risk read cnt: {e}")))?;
                    Ok(cnt)
                })
            }
            Repo::Postgres(_) => {
                let bucket = bucket.to_string();
                self.txn_serializable_pg(move |tx| {
                    let bucket = bucket.clone();
                    Box::pin(async move {
                        let row: (i64,) = sqlx::query_as(
                            "INSERT INTO risk_rate_counters (bucket, window_id, cnt) VALUES ($1, $2, 1)
                             ON CONFLICT (bucket, window_id) DO UPDATE SET cnt = risk_rate_counters.cnt + 1
                             RETURNING cnt",
                        )
                        .bind(&bucket)
                        .bind(window_id)
                        .fetch_one(&mut **tx)
                        .await
                        .map_err(|e| {
                            match e {
                                sqlx::Error::Database(ref db_err)
                                    if db_err.code().as_deref() == Some("40001") =>
                                {
                                    RepoError::Backend("40001 serialization_failure".into())
                                }
                                _ => RepoError::Backend(format!("postgres risk inc: {e}")),
                            }
                        })?;
                        Ok(row.0)
                    })
                })
                .await
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

    // ─── M2: agent_pop_challenges ──────────────────────────────────────────
    //
    // Low-risk module: one-time PoP challenges with GC-on-expiry. Take helper
    // is single-row delete-by-id with a freshness check; the SQLite path keeps
    // its existing INSERT/DELETE flow via `ajwt_support::insert_pop_challenge`
    // and `ajwt_support::take_pop_challenge` (those wrap in `BEGIN IMMEDIATE`
    // for safety even though the operations are intrinsically atomic).

    /// Background-GC sweep for `agent_pop_challenges`. Returns rows removed.
    pub async fn prune_pop_challenges(&self, now: i64) -> Result<u64, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                let n = conn
                    .execute(
                        "DELETE FROM agent_pop_challenges WHERE exp < ?1",
                        rusqlite::params![now],
                    )
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(n as u64)
            }
            Repo::Postgres(pool) => {
                let r = sqlx::query("DELETE FROM agent_pop_challenges WHERE exp < $1")
                    .bind(now)
                    .execute(pool)
                    .await
                    .map_err(|e| RepoError::Backend(format!("postgres prune pop: {e}")))?;
                Ok(r.rows_affected())
            }
        }
    }

    /// Insert a one-time PoP challenge after GC. Returns the stored `exp`.
    pub async fn insert_pop_challenge(
        &self,
        id: &str,
        agent_id: &str,
        challenge: &str,
        now: i64,
        ttl_secs: i64,
    ) -> Result<i64, RepoError> {
        let exp = now + ttl_secs;
        match self {
            Repo::Sqlite(_) => {
                let id = id.to_string();
                let agent_id = agent_id.to_string();
                let challenge = challenge.to_string();
                self.txn_immediate_sqlite(move |conn| {
                    conn.execute(
                        "DELETE FROM agent_pop_challenges WHERE exp < ?1",
                        rusqlite::params![now],
                    )
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                    conn.execute(
                        "INSERT INTO agent_pop_challenges (id, agent_id, challenge, exp) \
                         VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params![id, agent_id, challenge, exp],
                    )
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
                    Ok(exp)
                })
            }
            Repo::Postgres(_) => {
                let id = id.to_string();
                let agent_id = agent_id.to_string();
                let challenge = challenge.to_string();
                self.txn_serializable_pg(move |tx| {
                    let id = id.clone();
                    let agent_id = agent_id.clone();
                    let challenge = challenge.clone();
                    Box::pin(async move {
                        sqlx::query("DELETE FROM agent_pop_challenges WHERE exp < $1")
                            .bind(now)
                            .execute(&mut **tx)
                            .await
                            .map_err(|e| RepoError::Backend(format!("pg pop gc: {e}")))?;
                        sqlx::query(
                            "INSERT INTO agent_pop_challenges (id, agent_id, challenge, exp) \
                             VALUES ($1, $2, $3, $4)",
                        )
                        .bind(&id)
                        .bind(&agent_id)
                        .bind(&challenge)
                        .bind(exp)
                        .execute(&mut **tx)
                        .await
                        .map_err(|e| RepoError::Backend(format!("pg pop insert: {e}")))?;
                        Ok(exp)
                    })
                })
                .await
            }
        }
    }

    /// Take (load + delete) a one-time PoP challenge under a serializable txn.
    /// Returns Err(`Replay`) when the challenge is missing, expired, or bound
    /// to a different agent. Postgres uses `FOR UPDATE` + conditional DELETE
    /// `RETURNING` to guarantee at most one taker.
    pub async fn take_pop_challenge(
        &self,
        challenge_id: &str,
        expected_agent_id: &str,
        now: i64,
    ) -> Result<String, RepoError> {
        match self {
            Repo::Sqlite(_) => {
                let challenge_id = challenge_id.to_string();
                let expected_agent_id = expected_agent_id.to_string();
                self.txn_immediate_sqlite(move |conn| {
                    let (challenge, agent_id, exp): (String, String, i64) = conn
                        .query_row(
                            "SELECT challenge, agent_id, exp FROM agent_pop_challenges WHERE id = ?1",
                            rusqlite::params![challenge_id],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                        )
                        .map_err(|_| RepoError::Replay(
                            "unknown or expired pop_challenge_id".into(),
                        ))?;
                    if agent_id != expected_agent_id {
                        return Err(RepoError::Replay(
                            "pop challenge does not match agent".into(),
                        ));
                    }
                    if exp < now {
                        let _ = conn.execute(
                            "DELETE FROM agent_pop_challenges WHERE id = ?1",
                            rusqlite::params![challenge_id],
                        );
                        return Err(RepoError::Replay("pop challenge expired".into()));
                    }
                    let rows = conn
                        .execute(
                            "DELETE FROM agent_pop_challenges WHERE id = ?1",
                            rusqlite::params![challenge_id],
                        )
                        .map_err(|e| RepoError::Backend(e.to_string()))?;
                    if rows == 0 {
                        return Err(RepoError::Replay(
                            "pop challenge already taken".into(),
                        ));
                    }
                    Ok(challenge)
                })
            }
            Repo::Postgres(_) => {
                let challenge_id = challenge_id.to_string();
                let expected_agent_id = expected_agent_id.to_string();
                self.txn_serializable_pg(move |tx| {
                    let challenge_id = challenge_id.clone();
                    let expected_agent_id = expected_agent_id.clone();
                    Box::pin(async move {
                        // FOR UPDATE locks the row for the txn's life; the
                        // conditional DELETE … RETURNING below is what proves
                        // we are the sole taker.
                        let row: Option<(String, String, i64)> = sqlx::query_as(
                            "SELECT challenge, agent_id, exp FROM agent_pop_challenges \
                             WHERE id = $1 FOR UPDATE",
                        )
                        .bind(&challenge_id)
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(|e| RepoError::Backend(format!("pg pop select: {e}")))?;
                        let (challenge, agent_id, exp) = match row {
                            Some(t) => t,
                            None => return Err(RepoError::Replay(
                                "unknown or expired pop_challenge_id".into(),
                            )),
                        };
                        if agent_id != expected_agent_id {
                            return Err(RepoError::Replay(
                                "pop challenge does not match agent".into(),
                            ));
                        }
                        if exp < now {
                            let _ = sqlx::query("DELETE FROM agent_pop_challenges WHERE id = $1")
                                .bind(&challenge_id)
                                .execute(&mut **tx)
                                .await;
                            return Err(RepoError::Replay("pop challenge expired".into()));
                        }
                        let result: Option<(String,)> = sqlx::query_as(
                            "DELETE FROM agent_pop_challenges WHERE id = $1 RETURNING challenge",
                        )
                        .bind(&challenge_id)
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(|e| RepoError::Backend(format!("pg pop delete: {e}")))?;
                        match result {
                            Some(_) => Ok(challenge),
                            None => Err(RepoError::Replay(
                                "pop challenge already taken".into(),
                            )),
                        }
                    })
                })
                .await
            }
        }
    }

    // ─── M2: bank_attestation_nonces ───────────────────────────────────────
    //
    // UNIQUE-key consume. Primary key (provider_id, nonce) is the replay
    // detector; INSERT failing with UNIQUE violation maps to RepoError::Replay.

    pub async fn consume_bank_attestation_nonce(
        &self,
        provider_id: &str,
        nonce: &str,
        issued_at: i64,
    ) -> Result<(), RepoError> {
        if provider_id.is_empty() || nonce.is_empty() {
            return Err(RepoError::Backend("missing provider_id or nonce".into()));
        }
        if nonce.len() > 256 {
            return Err(RepoError::Backend("attestation nonce too long".into()));
        }
        match self {
            Repo::Sqlite(_) => {
                let provider_id = provider_id.to_string();
                let nonce = nonce.to_string();
                self.txn_immediate_sqlite(move |conn| {
                    conn.execute(
                        "INSERT INTO bank_attestation_nonces (provider_id, nonce, issued_at) \
                         VALUES (?1, ?2, ?3)",
                        rusqlite::params![provider_id, nonce, issued_at],
                    )
                    .map_err(|e| {
                        let s = e.to_string();
                        if s.contains("UNIQUE") || s.contains("PRIMARY KEY") {
                            RepoError::Replay(
                                "Replay detected for bank attestation nonce".into(),
                            )
                        } else {
                            RepoError::Backend(s)
                        }
                    })?;
                    Ok(())
                })
            }
            Repo::Postgres(_) => {
                let provider_id = provider_id.to_string();
                let nonce = nonce.to_string();
                self.txn_serializable_pg(move |tx| {
                    let provider_id = provider_id.clone();
                    let nonce = nonce.clone();
                    Box::pin(async move {
                        let result = sqlx::query(
                            "INSERT INTO bank_attestation_nonces (provider_id, nonce, issued_at) \
                             VALUES ($1, $2, $3)",
                        )
                        .bind(&provider_id)
                        .bind(&nonce)
                        .bind(issued_at)
                        .execute(&mut **tx)
                        .await;
                        match result {
                            Ok(_) => Ok(()),
                            Err(sqlx::Error::Database(db_err))
                                if db_err.is_unique_violation() =>
                            {
                                Err(RepoError::Replay(
                                    "Replay detected for bank attestation nonce".into(),
                                ))
                            }
                            Err(sqlx::Error::Database(db_err))
                                if db_err.code().as_deref() == Some("40001") =>
                            {
                                Err(RepoError::Backend("40001 serialization_failure".into()))
                            }
                            Err(e) => Err(RepoError::Backend(format!(
                                "pg bank attestation insert: {e}"
                            ))),
                        }
                    })
                })
                .await
            }
        }
    }

    // ─── M2: consent_log token consume ─────────────────────────────────────
    //
    // The TOCTOU pattern: mark `token_used=1` only if the row currently has
    // `token_used=0 AND revoked=0 AND not expired`. Postgres uses
    // `SELECT … FOR UPDATE` to lock the row, then conditional UPDATE …
    // RETURNING to confirm the flag actually flipped. The RETURNING row count
    // is the authoritative TOCTOU oracle: only one txn can flip 0→1.
    //
    // Returns the consent record (user_key_image, site_name, issuing_agent_id,
    // requested_claims_json) on success. Error variants distinguish replay
    // (already used / revoked / expired) from backend.

    #[allow(clippy::type_complexity)]
    pub async fn consume_consent_token(
        &self,
        consent_token: &str,
        now: i64,
    ) -> Result<(String, String, Option<String>, String), RepoError> {
        if consent_token.is_empty() {
            return Err(RepoError::Backend("missing consent token".into()));
        }
        if consent_token.len() > 256 {
            return Err(RepoError::Backend("consent token too long".into()));
        }
        match self {
            Repo::Sqlite(_) => {
                let consent_token = consent_token.to_string();
                self.txn_immediate_sqlite(move |conn| {
                    let rows = conn
                        .execute(
                            "UPDATE consent_log SET token_used = 1 \
                             WHERE consent_token = ?1 AND token_used = 0 AND revoked = 0 \
                             AND (consent_expires_at = 0 OR consent_expires_at > ?2)",
                            rusqlite::params![consent_token, now],
                        )
                        .map_err(|e| RepoError::Backend(e.to_string()))?;
                    if rows == 0 {
                        // Distinguish replay/expired/revoked for caller mapping.
                        let status = conn.query_row(
                            "SELECT token_used, revoked, consent_expires_at FROM consent_log \
                             WHERE consent_token = ?1",
                            rusqlite::params![consent_token],
                            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
                        );
                        return match status {
                            Ok((_, 1, _)) => {
                                Err(RepoError::Replay("Consent token revoked".into()))
                            }
                            Ok((1, _, _)) => {
                                Err(RepoError::Replay("Consent token already used".into()))
                            }
                            Ok((_, _, exp)) if exp > 0 && now > exp => {
                                Err(RepoError::Replay("Consent token expired".into()))
                            }
                            _ => Err(RepoError::Replay(
                                "Invalid or expired consent token".into(),
                            )),
                        };
                    }
                    let row: (String, String, Option<String>, String) = conn
                        .query_row(
                            "SELECT user_key_image, site_name, issuing_agent_id, requested_claims_json \
                             FROM consent_log WHERE consent_token = ?1",
                            rusqlite::params![consent_token],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                        )
                        .map_err(|_| RepoError::Replay(
                            "Invalid or expired consent token".into(),
                        ))?;
                    Ok(row)
                })
            }
            Repo::Postgres(_) => {
                let consent_token = consent_token.to_string();
                self.txn_serializable_pg(move |tx| {
                    let consent_token = consent_token.clone();
                    Box::pin(async move {
                        // FOR UPDATE locks the row; RETURNING confirms we
                        // flipped 0→1. If RETURNING is empty, the row is
                        // either missing or already consumed/revoked/expired.
                        let claimed: Option<(String, String, Option<String>, String)> =
                            sqlx::query_as(
                                "UPDATE consent_log SET token_used = 1 \
                                 WHERE consent_token = $1 AND token_used = 0 AND revoked = 0 \
                                 AND (consent_expires_at = 0 OR consent_expires_at > $2) \
                                 RETURNING user_key_image, site_name, issuing_agent_id, \
                                           requested_claims_json",
                            )
                            .bind(&consent_token)
                            .bind(now)
                            .fetch_optional(&mut **tx)
                            .await
                            .map_err(|e| match e {
                                sqlx::Error::Database(ref db_err)
                                    if db_err.code().as_deref() == Some("40001") =>
                                {
                                    RepoError::Backend("40001 serialization_failure".into())
                                }
                                _ => RepoError::Backend(format!("pg consent claim: {e}")),
                            })?;
                        if let Some(row) = claimed {
                            return Ok(row);
                        }
                        // Disambiguate the failure path.
                        let status: Option<(i64, i64, i64)> = sqlx::query_as(
                            "SELECT token_used, revoked, consent_expires_at FROM consent_log \
                             WHERE consent_token = $1",
                        )
                        .bind(&consent_token)
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(|e| RepoError::Backend(format!("pg consent status: {e}")))?;
                        Err(match status {
                            Some((_, 1, _)) => {
                                RepoError::Replay("Consent token revoked".into())
                            }
                            Some((1, _, _)) => {
                                RepoError::Replay("Consent token already used".into())
                            }
                            Some((_, _, exp)) if exp > 0 && now > exp => {
                                RepoError::Replay("Consent token expired".into())
                            }
                            _ => RepoError::Replay(
                                "Invalid or expired consent token".into(),
                            ),
                        })
                    })
                })
                .await
            }
        }
    }

    /// Insert a pending consent request. Used at /kyc/request to enrol a new
    /// request_id; the consent_token is filled later when the user grants.
    pub async fn insert_pending_consent(
        &self,
        request_id: &str,
        site_name: &str,
        requested_claims_json: &str,
    ) -> Result<(), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute(
                    "INSERT INTO consent_log (request_id, user_key_image, site_name, \
                     requested_claims_json, granted_at, token_used, revoked) \
                     VALUES (?1, '', ?2, ?3, 0, 0, 0)",
                    rusqlite::params![request_id, site_name, requested_claims_json],
                )
                .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(())
            }
            Repo::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO consent_log (request_id, user_key_image, site_name, \
                     requested_claims_json, granted_at, token_used, revoked) \
                     VALUES ($1, '', $2, $3, 0, 0, 0)",
                )
                .bind(request_id)
                .bind(site_name)
                .bind(requested_claims_json)
                .execute(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg insert consent: {e}")))?;
                Ok(())
            }
        }
    }

    // ─── M2: agent_payment_authorizations ──────────────────────────────────
    //
    // Same TOCTOU pattern as consent_log: flip `consumed=0 → 1` only once.
    // Postgres uses FOR UPDATE + RETURNING; SQLite uses BEGIN IMMEDIATE +
    // conditional UPDATE.

    pub async fn consume_payment_authorization(
        &self,
        auth_id: &str,
        now: i64,
    ) -> Result<(), RepoError> {
        if auth_id.is_empty() {
            return Err(RepoError::Backend("missing auth_id".into()));
        }
        match self {
            Repo::Sqlite(_) => {
                let auth_id = auth_id.to_string();
                self.txn_immediate_sqlite(move |conn| {
                    let rows = conn
                        .execute(
                            "UPDATE agent_payment_authorizations SET consumed = 1 \
                             WHERE auth_id = ?1 AND consumed = 0 AND expires_at > ?2",
                            rusqlite::params![auth_id, now],
                        )
                        .map_err(|e| RepoError::Backend(e.to_string()))?;
                    if rows == 0 {
                        return Err(RepoError::Replay(
                            "Authorization already consumed or expired".into(),
                        ));
                    }
                    Ok(())
                })
            }
            Repo::Postgres(_) => {
                let auth_id = auth_id.to_string();
                self.txn_serializable_pg(move |tx| {
                    let auth_id = auth_id.clone();
                    Box::pin(async move {
                        let claimed: Option<(String,)> = sqlx::query_as(
                            "UPDATE agent_payment_authorizations SET consumed = 1 \
                             WHERE auth_id = $1 AND consumed = 0 AND expires_at > $2 \
                             RETURNING auth_id",
                        )
                        .bind(&auth_id)
                        .bind(now)
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(|e| match e {
                            sqlx::Error::Database(ref db_err)
                                if db_err.code().as_deref() == Some("40001") =>
                            {
                                RepoError::Backend("40001 serialization_failure".into())
                            }
                            _ => RepoError::Backend(format!("pg payauth consume: {e}")),
                        })?;
                        if claimed.is_none() {
                            return Err(RepoError::Replay(
                                "Authorization already consumed or expired".into(),
                            ));
                        }
                        Ok(())
                    })
                })
                .await
            }
        }
    }

    /// Insert a new single-use payment authorization. Unique on `auth_id` and
    /// `jti` — uniqueness violations surface as `RepoError::Replay`.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_payment_authorization(
        &self,
        auth_id: &str,
        agent_id: &str,
        jti: &str,
        amount_minor: i64,
        currency: &str,
        merchant_id: &str,
        payment_ref: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute(
                    "INSERT INTO agent_payment_authorizations (auth_id, agent_id, jti, \
                     amount_minor, currency, merchant_id, payment_ref, created_at, \
                     expires_at, consumed) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
                    rusqlite::params![
                        auth_id, agent_id, jti, amount_minor, currency, merchant_id,
                        payment_ref, created_at, expires_at,
                    ],
                )
                .map_err(|e| {
                    let s = e.to_string();
                    if s.contains("UNIQUE") || s.contains("PRIMARY KEY") {
                        RepoError::Replay("payment authorization already exists".into())
                    } else {
                        RepoError::Backend(s)
                    }
                })?;
                Ok(())
            }
            Repo::Postgres(pool) => {
                let res = sqlx::query(
                    "INSERT INTO agent_payment_authorizations (auth_id, agent_id, jti, \
                     amount_minor, currency, merchant_id, payment_ref, created_at, \
                     expires_at, consumed) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0)",
                )
                .bind(auth_id)
                .bind(agent_id)
                .bind(jti)
                .bind(amount_minor)
                .bind(currency)
                .bind(merchant_id)
                .bind(payment_ref)
                .bind(created_at)
                .bind(expires_at)
                .execute(pool)
                .await;
                match res {
                    Ok(_) => Ok(()),
                    Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                        Err(RepoError::Replay(
                            "payment authorization already exists".into(),
                        ))
                    }
                    Err(e) => Err(RepoError::Backend(format!(
                        "pg insert payment auth: {e}"
                    ))),
                }
            }
        }
    }

    // ─── M3: credential_codes ─────────────────────────────────────────────
    //
    // Single-use `claimed` flag flip — exact mirror of M2 payment_auth pattern.

    /// Attempt to flip credential_codes.claimed 0→1 for the given key image.
    /// Returns Ok(true) if this caller won the race, Ok(false) if the row
    /// was already claimed (caller should re-check `user_credentials`).
    pub async fn claim_credential_code(&self, key_image_hex: &str) -> Result<bool, RepoError> {
        if key_image_hex.is_empty() {
            return Err(RepoError::Backend("missing key_image_hex".into()));
        }
        match self {
            Repo::Sqlite(_) => {
                let key = key_image_hex.to_string();
                self.txn_immediate_sqlite(move |conn| {
                    let rows = conn
                        .execute(
                            "UPDATE credential_codes SET claimed = 1 \
                             WHERE key_image_hex = ?1 AND claimed = 0",
                            rusqlite::params![key],
                        )
                        .map_err(|e| RepoError::Backend(e.to_string()))?;
                    Ok(rows == 1)
                })
            }
            Repo::Postgres(_) => {
                let key = key_image_hex.to_string();
                self.txn_serializable_pg(move |tx| {
                    let key = key.clone();
                    Box::pin(async move {
                        let claimed: Option<(String,)> = sqlx::query_as(
                            "UPDATE credential_codes SET claimed = 1 \
                             WHERE key_image_hex = $1 AND claimed = 0 \
                             RETURNING key_image_hex",
                        )
                        .bind(&key)
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(|e| match e {
                            sqlx::Error::Database(ref db_err)
                                if db_err.code().as_deref() == Some("40001") =>
                            {
                                RepoError::Backend("40001 serialization_failure".into())
                            }
                            _ => RepoError::Backend(format!("pg credential claim: {e}")),
                        })?;
                        Ok(claimed.is_some())
                    })
                })
                .await
            }
        }
    }

    /// Release a previously claimed credential code so the user can retry.
    /// Used on the failure paths in the /credential/claim flow.
    pub async fn release_credential_code(&self, key_image_hex: &str) -> Result<(), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute(
                    "UPDATE credential_codes SET claimed = 0 \
                     WHERE key_image_hex = ?1 AND claimed = 1",
                    rusqlite::params![key_image_hex],
                )
                .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(())
            }
            Repo::Postgres(pool) => {
                sqlx::query(
                    "UPDATE credential_codes SET claimed = 0 \
                     WHERE key_image_hex = $1 AND claimed = 1",
                )
                .bind(key_image_hex)
                .execute(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg release credential: {e}")))?;
                Ok(())
            }
        }
    }

    /// Look up the pre-auth code + subject DID for a credential request.
    pub async fn select_credential_code(
        &self,
        key_image_hex: &str,
    ) -> Result<Option<(String, String)>, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                let row = conn
                    .query_row(
                        "SELECT pre_auth_code, subject_did FROM credential_codes \
                         WHERE key_image_hex = ?1",
                        rusqlite::params![key_image_hex],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                    )
                    .ok();
                Ok(row)
            }
            Repo::Postgres(pool) => {
                let row: Option<(String, String)> = sqlx::query_as(
                    "SELECT pre_auth_code, subject_did FROM credential_codes \
                     WHERE key_image_hex = $1",
                )
                .bind(key_image_hex)
                .fetch_optional(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg sel credential code: {e}")))?;
                Ok(row)
            }
        }
    }

    // ─── M3: users + user_credentials + user_registrations ────────────────

    /// Returns true if a user row exists for the key image.
    pub async fn user_exists(&self, key_image_hex: &str) -> Result<bool, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                let n: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM users WHERE key_image_hex = ?1",
                        rusqlite::params![key_image_hex],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);
                Ok(n > 0)
            }
            Repo::Postgres(pool) => {
                let row: (i64,) = sqlx::query_as(
                    "SELECT COUNT(*)::BIGINT FROM users WHERE key_image_hex = $1",
                )
                .bind(key_image_hex)
                .fetch_one(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg user_exists: {e}")))?;
                Ok(row.0 > 0)
            }
        }
    }

    /// Upsert a user row (idempotent — re-registration overrides metadata).
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_user(
        &self,
        key_image_hex: &str,
        public_key_hex: &str,
        first_name: &str,
        last_name: &str,
        email: &str,
        date_of_birth: &str,
        nationality: &str,
    ) -> Result<(), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute(
                    "INSERT INTO users (key_image_hex, public_key_hex, first_name, last_name, \
                     email, date_of_birth, nationality) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                     ON CONFLICT(key_image_hex) DO UPDATE SET \
                       public_key_hex = excluded.public_key_hex, \
                       first_name = excluded.first_name, \
                       last_name = excluded.last_name, \
                       email = excluded.email, \
                       date_of_birth = excluded.date_of_birth, \
                       nationality = excluded.nationality",
                    rusqlite::params![
                        key_image_hex,
                        public_key_hex,
                        first_name,
                        last_name,
                        email,
                        date_of_birth,
                        nationality
                    ],
                )
                .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(())
            }
            Repo::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO users (key_image_hex, public_key_hex, first_name, last_name, \
                     email, date_of_birth, nationality) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7) \
                     ON CONFLICT (key_image_hex) DO UPDATE SET \
                       public_key_hex = EXCLUDED.public_key_hex, \
                       first_name = EXCLUDED.first_name, \
                       last_name = EXCLUDED.last_name, \
                       email = EXCLUDED.email, \
                       date_of_birth = EXCLUDED.date_of_birth, \
                       nationality = EXCLUDED.nationality",
                )
                .bind(key_image_hex)
                .bind(public_key_hex)
                .bind(first_name)
                .bind(last_name)
                .bind(email)
                .bind(date_of_birth)
                .bind(nationality)
                .execute(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg upsert user: {e}")))?;
                Ok(())
            }
        }
    }

    /// Cache the issuer-minted VC for a user (idempotent upsert by key image).
    pub async fn upsert_user_credential(
        &self,
        key_image_hex: &str,
        credential_json: &str,
        issued_at: i64,
    ) -> Result<(), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute(
                    "INSERT OR REPLACE INTO user_credentials (key_image_hex, credential_json, issued_at) \
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![key_image_hex, credential_json, issued_at],
                )
                .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(())
            }
            Repo::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO user_credentials (key_image_hex, credential_json, issued_at) \
                     VALUES ($1, $2, $3) \
                     ON CONFLICT (key_image_hex) DO UPDATE SET \
                       credential_json = EXCLUDED.credential_json, \
                       issued_at = EXCLUDED.issued_at",
                )
                .bind(key_image_hex)
                .bind(credential_json)
                .bind(issued_at)
                .execute(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg upsert user cred: {e}")))?;
                Ok(())
            }
        }
    }

    /// Fetch the cached VC, if any.
    pub async fn select_user_credential(
        &self,
        key_image_hex: &str,
    ) -> Result<Option<String>, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                let row = conn
                    .query_row(
                        "SELECT credential_json FROM user_credentials WHERE key_image_hex = ?1",
                        rusqlite::params![key_image_hex],
                        |r| r.get::<_, String>(0),
                    )
                    .ok();
                Ok(row)
            }
            Repo::Postgres(pool) => {
                let row: Option<(String,)> = sqlx::query_as(
                    "SELECT credential_json FROM user_credentials WHERE key_image_hex = $1",
                )
                .bind(key_image_hex)
                .fetch_optional(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg sel user cred: {e}")))?;
                Ok(row.map(|t| t.0))
            }
        }
    }

    /// Append a user_registration row (idempotent — `INSERT OR IGNORE`).
    pub async fn insert_user_registration(
        &self,
        client_name: &str,
        user_key_image_hex: &str,
        source: &str,
        timestamp: i64,
    ) -> Result<(), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute(
                    "INSERT OR IGNORE INTO user_registrations (client_name, user_key_image_hex, source, timestamp) \
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![client_name, user_key_image_hex, source, timestamp],
                )
                .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(())
            }
            Repo::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO user_registrations (client_name, user_key_image_hex, source, timestamp) \
                     VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                )
                .bind(client_name)
                .bind(user_key_image_hex)
                .bind(source)
                .bind(timestamp)
                .execute(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg insert registration: {e}")))?;
                Ok(())
            }
        }
    }

    // ─── M3: merkle_leaves ────────────────────────────────────────────────

    /// Append a commitment to the merkle ledger (idempotent on UNIQUE).
    pub async fn insert_merkle_leaf(
        &self,
        commitment_hex: &str,
        registered_at: i64,
    ) -> Result<(), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute(
                    "INSERT OR IGNORE INTO merkle_leaves (commitment_hex, registered_at) \
                     VALUES (?1, ?2)",
                    rusqlite::params![commitment_hex, registered_at],
                )
                .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(())
            }
            Repo::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO merkle_leaves (commitment_hex, registered_at) \
                     VALUES ($1, $2) ON CONFLICT DO NOTHING",
                )
                .bind(commitment_hex)
                .bind(registered_at)
                .execute(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg insert merkle leaf: {e}")))?;
                Ok(())
            }
        }
    }

    // ─── M4: anchor tables (bitcoin / solana) ──────────────────────────────
    //
    // NOTE on autoincrement parity: SQLite's `INTEGER PRIMARY KEY AUTOINCREMENT`
    // produces a strictly monotonic gap-free sequence per table. Postgres's
    // `BIGSERIAL` (the canonical port) is *not* gap-free — the sequence
    // advances on rollback as well as commit. Callers must not assume the
    // primary-key id is a contiguous count of historical rows. Both anchor
    // tables here use TEXT `anchor_id` as the public reference, so this is
    // an internal-only concern.

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_bitcoin_anchor(
        &self,
        anchor_id: &str,
        merkle_root_hex: &str,
        provider: &str,
        network: &str,
        op_return_hex: &str,
        txid: &str,
        broadcast: bool,
        no_real_money: bool,
        created_at: i64,
        ots_receipt_blob: Option<&[u8]>,
        ots_calendar_url: &str,
        ots_upgraded: bool,
    ) -> Result<(), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute(
                    "INSERT INTO bitcoin_merkle_anchors (anchor_id, merkle_root_hex, provider, \
                     network, op_return_hex, txid, broadcast, no_real_money, created_at, \
                     ots_receipt_blob, ots_calendar_url, ots_upgraded) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    rusqlite::params![
                        anchor_id,
                        merkle_root_hex,
                        provider,
                        network,
                        op_return_hex,
                        txid,
                        broadcast as i64,
                        no_real_money as i64,
                        created_at,
                        ots_receipt_blob,
                        ots_calendar_url,
                        ots_upgraded as i64,
                    ],
                )
                .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(())
            }
            Repo::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO bitcoin_merkle_anchors (anchor_id, merkle_root_hex, provider, \
                     network, op_return_hex, txid, broadcast, no_real_money, created_at, \
                     ots_receipt_blob, ots_calendar_url, ots_upgraded) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                )
                .bind(anchor_id)
                .bind(merkle_root_hex)
                .bind(provider)
                .bind(network)
                .bind(op_return_hex)
                .bind(txid)
                .bind(broadcast as i32)
                .bind(no_real_money as i32)
                .bind(created_at)
                .bind(ots_receipt_blob)
                .bind(ots_calendar_url)
                .bind(ots_upgraded as i32)
                .execute(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg insert btc anchor: {e}")))?;
                Ok(())
            }
        }
    }

    pub async fn insert_solana_anchor(
        &self,
        anchor_id: &str,
        merkle_root_hex: &str,
        network: &str,
        signature: &str,
        slot: i64,
        confirmed: bool,
        created_at: i64,
    ) -> Result<(), RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                conn.execute(
                    "INSERT INTO solana_merkle_anchors (anchor_id, merkle_root_hex, network, \
                     signature, slot, confirmed, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        anchor_id,
                        merkle_root_hex,
                        network,
                        signature,
                        slot,
                        confirmed as i64,
                        created_at,
                    ],
                )
                .map_err(|e| RepoError::Backend(e.to_string()))?;
                Ok(())
            }
            Repo::Postgres(pool) => {
                sqlx::query(
                    "INSERT INTO solana_merkle_anchors (anchor_id, merkle_root_hex, network, \
                     signature, slot, confirmed, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                )
                .bind(anchor_id)
                .bind(merkle_root_hex)
                .bind(network)
                .bind(signature)
                .bind(slot)
                .bind(confirmed as i32)
                .bind(created_at)
                .execute(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg insert sol anchor: {e}")))?;
                Ok(())
            }
        }
    }

    // ─── M4: agent_action_receipts ─────────────────────────────────────────

    /// Returns true if a receipt with the given id+action_hash pair exists.
    /// Used by the agent-action validator to detect replays.
    pub async fn agent_action_receipt_exists(
        &self,
        receipt_id: &str,
        action_hash: &str,
    ) -> Result<bool, RepoError> {
        match self {
            Repo::Sqlite(db) => {
                let conn = db.lock().map_err(|e| RepoError::Backend(e.to_string()))?;
                let n: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM agent_action_receipts \
                         WHERE receipt_id = ?1 AND action_hash = ?2",
                        rusqlite::params![receipt_id, action_hash],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);
                Ok(n > 0)
            }
            Repo::Postgres(pool) => {
                let row: (i64,) = sqlx::query_as(
                    "SELECT COUNT(*)::BIGINT FROM agent_action_receipts \
                     WHERE receipt_id = $1 AND action_hash = $2",
                )
                .bind(receipt_id)
                .bind(action_hash)
                .fetch_one(pool)
                .await
                .map_err(|e| RepoError::Backend(format!("pg receipt exists: {e}")))?;
                Ok(row.0 > 0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_db_at;

    /// Build a unique-path Repo::Sqlite for parallel test isolation.
    fn build_test_repo(test_name: &str) -> Repo {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path = std::env::temp_dir().join(format!(
            "sauron-repo-test-{pid}-{nanos}-{test_name}.db"
        ));
        // Ensure clean slate.
        let _ = std::fs::remove_file(&path);
        let handle = open_db_at(path.to_str().unwrap(), 2);
        Repo::Sqlite(Arc::new(handle))
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn test_repo_consume_call_nonce_first_use_succeeds() {
        let repo = build_test_repo("first_use_ok");
        rt().block_on(async {
            let r = repo
                .consume_call_nonce("agent-1", "nonce-abc", 9_999_999_999)
                .await;
            assert!(r.is_ok(), "first use must succeed: {r:?}");
        });
    }

    #[test]
    fn test_repo_consume_call_nonce_replay_rejected() {
        let repo = build_test_repo("replay_rejected");
        rt().block_on(async {
            repo.consume_call_nonce("agent-1", "nonce-xyz", 9_999_999_999)
                .await
                .expect("first insert ok");
            let r2 = repo
                .consume_call_nonce("agent-1", "nonce-xyz", 9_999_999_999)
                .await;
            match r2 {
                Err(RepoError::Replay(_)) => {}
                other => panic!("expected Replay error, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_consume_call_nonce_rejects_empty_nonce() {
        let repo = build_test_repo("empty_nonce");
        rt().block_on(async {
            let r = repo.consume_call_nonce("agent-1", "", 1).await;
            match r {
                Err(RepoError::Backend(s)) => assert!(s.contains("missing")),
                other => panic!("expected Backend missing-nonce, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_consume_call_nonce_rejects_oversized_nonce() {
        let repo = build_test_repo("oversize_nonce");
        rt().block_on(async {
            let huge = "a".repeat(129);
            let r = repo.consume_call_nonce("agent-1", &huge, 1).await;
            match r {
                Err(RepoError::Backend(s)) => assert!(s.contains("too long")),
                other => panic!("expected Backend too-long, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_prune_call_nonces_removes_expired_only() {
        let repo = build_test_repo("prune_expired");
        rt().block_on(async {
            // Two expired, one fresh.
            repo.consume_call_nonce("agent-1", "old-1", 100).await.unwrap();
            repo.consume_call_nonce("agent-1", "old-2", 200).await.unwrap();
            repo.consume_call_nonce("agent-1", "fresh", 9_999_999_999)
                .await
                .unwrap();

            let removed = repo.prune_call_nonces(1_000).await.expect("prune ok");
            assert_eq!(removed, 2, "must prune exactly the two expired rows");

            // The fresh row is still effective: re-using it must replay-fail.
            let r = repo
                .consume_call_nonce("agent-1", "fresh", 9_999_999_999)
                .await;
            assert!(matches!(r, Err(RepoError::Replay(_))));
        });
    }

    #[test]
    fn test_repo_is_postgres_false_for_sqlite_backend() {
        let repo = build_test_repo("not_postgres");
        assert!(!repo.is_postgres());
    }

    // ─── M1 new helpers ───────────────────────────────────────────────────

    #[test]
    fn test_repo_consume_ajwt_jti_first_use_ok() {
        let repo = build_test_repo("ajwt_first_ok");
        rt().block_on(async {
            let r = repo.consume_ajwt_jti("jti-1", 9_999_999_999).await;
            assert!(r.is_ok(), "first jti claim ok: {r:?}");
        });
    }

    #[test]
    fn test_repo_consume_ajwt_jti_replay_rejected() {
        let repo = build_test_repo("ajwt_replay");
        rt().block_on(async {
            repo.consume_ajwt_jti("jti-replay", 9_999_999_999)
                .await
                .expect("first ok");
            let r = repo.consume_ajwt_jti("jti-replay", 9_999_999_999).await;
            match r {
                Err(RepoError::Replay(_)) => {}
                other => panic!("expected Replay, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_consume_ajwt_jti_rejects_empty() {
        let repo = build_test_repo("ajwt_empty");
        rt().block_on(async {
            let r = repo.consume_ajwt_jti("", 1).await;
            match r {
                Err(RepoError::Backend(s)) => assert!(s.contains("missing")),
                other => panic!("expected Backend missing, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_risk_increment_increments_monotonically() {
        let repo = build_test_repo("risk_inc_mono");
        rt().block_on(async {
            let n1 = repo.risk_increment("bucket-A", 100).await.unwrap();
            let n2 = repo.risk_increment("bucket-A", 100).await.unwrap();
            let n3 = repo.risk_increment("bucket-A", 100).await.unwrap();
            assert_eq!(n1, 1);
            assert_eq!(n2, 2);
            assert_eq!(n3, 3);
        });
    }

    #[test]
    fn test_repo_risk_increment_isolates_by_bucket_and_window() {
        let repo = build_test_repo("risk_inc_isolate");
        rt().block_on(async {
            let a = repo.risk_increment("bucket-A", 200).await.unwrap();
            let b = repo.risk_increment("bucket-B", 200).await.unwrap();
            let a_w2 = repo.risk_increment("bucket-A", 201).await.unwrap();
            assert_eq!(a, 1);
            assert_eq!(b, 1);
            assert_eq!(a_w2, 1);
        });
    }

    #[test]
    fn test_repo_risk_increment_rejects_bad_bucket() {
        let repo = build_test_repo("risk_inc_bad");
        rt().block_on(async {
            let huge = "a".repeat(129);
            let r = repo.risk_increment(&huge, 1).await;
            match r {
                Err(RepoError::Backend(s)) => assert!(s.contains("invalid")),
                other => panic!("expected Backend invalid, got: {other:?}"),
            }
        });
    }

    // ─── M2: agent_pop_challenges ─────────────────────────────────────────

    #[test]
    fn test_repo_pop_insert_then_take_returns_challenge() {
        let repo = build_test_repo("pop_insert_take");
        rt().block_on(async {
            let exp = repo
                .insert_pop_challenge("pch_1", "agent-1", "chal-abc", 1_000, 300)
                .await
                .expect("insert ok");
            assert_eq!(exp, 1_300);
            let got = repo
                .take_pop_challenge("pch_1", "agent-1", 1_001)
                .await
                .expect("take ok");
            assert_eq!(got, "chal-abc");
        });
    }

    #[test]
    fn test_repo_pop_take_twice_replays() {
        let repo = build_test_repo("pop_take_twice");
        rt().block_on(async {
            repo.insert_pop_challenge("pch_2", "agent-1", "chal", 1_000, 300)
                .await
                .unwrap();
            repo.take_pop_challenge("pch_2", "agent-1", 1_001)
                .await
                .unwrap();
            match repo.take_pop_challenge("pch_2", "agent-1", 1_001).await {
                Err(RepoError::Replay(_)) => {}
                other => panic!("expected Replay on second take, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_pop_take_wrong_agent_rejected() {
        let repo = build_test_repo("pop_take_wrong_agent");
        rt().block_on(async {
            repo.insert_pop_challenge("pch_3", "agent-A", "chal", 1_000, 300)
                .await
                .unwrap();
            match repo.take_pop_challenge("pch_3", "agent-B", 1_001).await {
                Err(RepoError::Replay(s)) => assert!(s.contains("match agent")),
                other => panic!("expected Replay match agent, got: {other:?}"),
            }
        });
    }

    // ─── M2: bank_attestation_nonces ──────────────────────────────────────

    #[test]
    fn test_repo_consume_bank_attestation_nonce_first_use_ok() {
        let repo = build_test_repo("bank_attest_first");
        rt().block_on(async {
            let r = repo
                .consume_bank_attestation_nonce("bank-A", "nonce-1", 1_000)
                .await;
            assert!(r.is_ok(), "first use must succeed: {r:?}");
        });
    }

    #[test]
    fn test_repo_consume_bank_attestation_nonce_replay() {
        let repo = build_test_repo("bank_attest_replay");
        rt().block_on(async {
            repo.consume_bank_attestation_nonce("bank-A", "nonce-X", 1_000)
                .await
                .expect("first ok");
            match repo
                .consume_bank_attestation_nonce("bank-A", "nonce-X", 1_000)
                .await
            {
                Err(RepoError::Replay(_)) => {}
                other => panic!("expected Replay, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_consume_bank_attestation_nonce_different_provider_ok() {
        let repo = build_test_repo("bank_attest_diff_provider");
        rt().block_on(async {
            // Same nonce under a different provider_id is a different row.
            repo.consume_bank_attestation_nonce("bank-A", "shared", 1_000)
                .await
                .expect("A ok");
            let r = repo
                .consume_bank_attestation_nonce("bank-B", "shared", 1_000)
                .await;
            assert!(r.is_ok(), "(B, shared) is unique vs (A, shared): {r:?}");
        });
    }

    // ─── M2: consent_log ──────────────────────────────────────────────────

    /// Build a consent row with a known token. Uses a direct SQLite write
    /// (the production path goes through the granting flow, which is out of
    /// scope for the repo-level test).
    fn seed_consent_row(repo: &Repo, request_id: &str, token: &str, expires_at: i64) {
        if let Repo::Sqlite(db) = repo {
            let conn = db.lock().unwrap();
            conn.execute(
                "INSERT INTO consent_log (request_id, user_key_image, site_name, \
                 requested_claims_json, granted_at, consent_expires_at, consent_token, \
                 token_used, revoked) \
                 VALUES (?1, ?2, ?3, '[]', 1000, ?4, ?5, 0, 0)",
                rusqlite::params![request_id, "ki-1", "site-A", expires_at, token],
            )
            .unwrap();
        }
    }

    #[test]
    fn test_repo_consume_consent_token_first_use_returns_row() {
        let repo = build_test_repo("consent_first");
        rt().block_on(async {
            seed_consent_row(&repo, "req_1", "tok_1", 0);
            let (ki, site, agent, _claims) =
                repo.consume_consent_token("tok_1", 5_000).await.unwrap();
            assert_eq!(ki, "ki-1");
            assert_eq!(site, "site-A");
            assert!(agent.is_none());
        });
    }

    #[test]
    fn test_repo_consume_consent_token_replay_rejected() {
        let repo = build_test_repo("consent_replay");
        rt().block_on(async {
            seed_consent_row(&repo, "req_2", "tok_2", 0);
            repo.consume_consent_token("tok_2", 5_000).await.unwrap();
            match repo.consume_consent_token("tok_2", 5_000).await {
                Err(RepoError::Replay(s)) => assert!(s.contains("already used")),
                other => panic!("expected Replay already used, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_consume_consent_token_expired_rejected() {
        let repo = build_test_repo("consent_expired");
        rt().block_on(async {
            seed_consent_row(&repo, "req_3", "tok_3", 100);
            match repo.consume_consent_token("tok_3", 1_000).await {
                Err(RepoError::Replay(s)) => assert!(s.contains("expired")),
                other => panic!("expected Replay expired, got: {other:?}"),
            }
        });
    }

    // ─── M2: agent_payment_authorizations ─────────────────────────────────

    #[test]
    fn test_repo_payment_auth_insert_then_consume_once() {
        let repo = build_test_repo("payauth_insert_consume");
        rt().block_on(async {
            repo.insert_payment_authorization(
                "payauth_1", "agent-1", "jti-1", 1000, "EUR", "M1",
                "ref_1", 1_000, 9_999_999_999,
            )
            .await
            .expect("insert ok");
            repo.consume_payment_authorization("payauth_1", 1_001)
                .await
                .expect("first consume ok");
        });
    }

    #[test]
    fn test_repo_payment_auth_double_consume_rejected() {
        let repo = build_test_repo("payauth_double");
        rt().block_on(async {
            repo.insert_payment_authorization(
                "payauth_2", "agent-1", "jti-2", 1000, "EUR", "M1",
                "ref_2", 1_000, 9_999_999_999,
            )
            .await
            .unwrap();
            repo.consume_payment_authorization("payauth_2", 1_001)
                .await
                .unwrap();
            match repo.consume_payment_authorization("payauth_2", 1_001).await {
                Err(RepoError::Replay(_)) => {}
                other => panic!("expected Replay, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_repo_payment_auth_duplicate_insert_replays() {
        let repo = build_test_repo("payauth_dup_insert");
        rt().block_on(async {
            repo.insert_payment_authorization(
                "payauth_3", "agent-1", "jti-3", 1000, "EUR", "M1",
                "ref_3", 1_000, 9_999_999_999,
            )
            .await
            .unwrap();
            match repo
                .insert_payment_authorization(
                    "payauth_3", "agent-2", "jti-3b", 2000, "EUR", "M1",
                    "ref_3b", 1_000, 9_999_999_999,
                )
                .await
            {
                Err(RepoError::Replay(_)) => {}
                other => panic!("expected Replay on PK conflict, got: {other:?}"),
            }
        });
    }

    // ─── M3: credential_codes ─────────────────────────────────────────────

    fn seed_credential_code(repo: &Repo, key_image: &str) {
        if let Repo::Sqlite(db) = repo {
            let conn = db.lock().unwrap();
            conn.execute(
                "INSERT INTO credential_codes (key_image_hex, pre_auth_code, subject_did, issued_at, claimed) \
                 VALUES (?1, 'pac_1', 'did:test:1', 1000, 0)",
                rusqlite::params![key_image],
            )
            .unwrap();
        }
    }

    #[test]
    fn test_repo_credential_code_first_claim_wins() {
        let repo = build_test_repo("cred_first_claim");
        rt().block_on(async {
            seed_credential_code(&repo, "ki-A");
            assert!(repo.claim_credential_code("ki-A").await.unwrap());
            assert!(!repo.claim_credential_code("ki-A").await.unwrap(),
                "second claim must lose the race");
        });
    }

    #[test]
    fn test_repo_credential_code_release_allows_retry() {
        let repo = build_test_repo("cred_release_retry");
        rt().block_on(async {
            seed_credential_code(&repo, "ki-B");
            assert!(repo.claim_credential_code("ki-B").await.unwrap());
            repo.release_credential_code("ki-B").await.unwrap();
            assert!(repo.claim_credential_code("ki-B").await.unwrap(),
                "after release, claim should succeed again");
        });
    }

    #[test]
    fn test_repo_select_credential_code_returns_pair() {
        let repo = build_test_repo("cred_select_pair");
        rt().block_on(async {
            seed_credential_code(&repo, "ki-C");
            let row = repo.select_credential_code("ki-C").await.unwrap();
            let (pac, did) = row.expect("row present");
            assert_eq!(pac, "pac_1");
            assert_eq!(did, "did:test:1");
            assert!(repo.select_credential_code("ki-missing").await.unwrap().is_none());
        });
    }

    // ─── M3: users + user_credentials + user_registrations ────────────────

    #[test]
    fn test_repo_users_upsert_idempotent() {
        let repo = build_test_repo("users_upsert");
        rt().block_on(async {
            assert!(!repo.user_exists("ki-1").await.unwrap());
            repo.upsert_user("ki-1", "pk", "A", "B", "a@b.c", "1990-01-01", "FR")
                .await
                .unwrap();
            assert!(repo.user_exists("ki-1").await.unwrap());
            // Upsert with new last_name overrides.
            repo.upsert_user("ki-1", "pk", "A", "Z", "a@b.c", "1990-01-01", "FR")
                .await
                .unwrap();
            assert!(repo.user_exists("ki-1").await.unwrap());
        });
    }

    #[test]
    fn test_repo_user_credential_upsert_and_select() {
        let repo = build_test_repo("ucred_upsert_sel");
        rt().block_on(async {
            assert!(repo.select_user_credential("ki-2").await.unwrap().is_none());
            repo.upsert_user_credential("ki-2", "{\"v\":1}", 1_000)
                .await
                .unwrap();
            assert_eq!(
                repo.select_user_credential("ki-2").await.unwrap(),
                Some("{\"v\":1}".to_string())
            );
        });
    }

    #[test]
    fn test_repo_user_registration_insert_idempotent() {
        let repo = build_test_repo("ureg_idem");
        rt().block_on(async {
            repo.insert_user_registration("bank-A", "ki-3", "bank_webhook", 1_000)
                .await
                .unwrap();
            // Same triple must be silently ignored, not error.
            repo.insert_user_registration("bank-A", "ki-3", "bank_webhook", 2_000)
                .await
                .unwrap();
        });
    }

    // ─── M3: merkle_leaves ────────────────────────────────────────────────

    #[test]
    fn test_repo_merkle_leaf_insert_idempotent() {
        let repo = build_test_repo("merkle_insert_idem");
        rt().block_on(async {
            repo.insert_merkle_leaf("c0ffee", 1_000).await.unwrap();
            // Duplicate commitment is silently ignored.
            repo.insert_merkle_leaf("c0ffee", 2_000).await.unwrap();
        });
    }

    // ─── M4: anchor tables ────────────────────────────────────────────────

    #[test]
    fn test_repo_bitcoin_anchor_insert() {
        let repo = build_test_repo("btc_anchor");
        rt().block_on(async {
            repo.insert_bitcoin_anchor(
                "btc_1", "root_hex", "mock", "regtest", "op_return", "txid_1",
                false, true, 1_000, None, "", false,
            )
            .await
            .expect("btc anchor insert");
        });
    }

    #[test]
    fn test_repo_solana_anchor_insert() {
        let repo = build_test_repo("sol_anchor");
        rt().block_on(async {
            repo.insert_solana_anchor(
                "sol_1", "root_hex", "devnet", "sig_1", 0, false, 1_000,
            )
            .await
            .expect("sol anchor insert");
        });
    }

    // ─── M4: agent_action_receipts ────────────────────────────────────────

    #[test]
    fn test_repo_receipt_exists_false_for_unknown() {
        let repo = build_test_repo("receipt_unknown");
        rt().block_on(async {
            assert!(!repo.agent_action_receipt_exists("rcp_1", "ah_1").await.unwrap());
        });
    }

    #[test]
    fn test_repo_receipt_exists_true_after_insert() {
        let repo = build_test_repo("receipt_inserted");
        rt().block_on(async {
            if let Repo::Sqlite(db) = &repo {
                let conn = db.lock().unwrap();
                conn.execute(
                    "INSERT INTO agent_action_receipts (receipt_id, action_hash, agent_id, \
                     ring_key_image_hex, policy_version, ajwt_jti, pop_jkt, status, signature, created_at) \
                     VALUES ('rcp_X', 'ah_X', 'agent-1', 'ki', 'v', 'jti', 'jkt', 'accepted', 'sig', 1000)",
                    [],
                )
                .unwrap();
            }
            assert!(repo.agent_action_receipt_exists("rcp_X", "ah_X").await.unwrap());
            assert!(!repo.agent_action_receipt_exists("rcp_X", "wrong_hash").await.unwrap());
        });
    }
}

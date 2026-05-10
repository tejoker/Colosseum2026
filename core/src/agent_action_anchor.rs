//! Periodic merkle commitment of `agent_action_receipts` to Bitcoin (OTS) and
//! Solana (Memo). Closes the audit-tampering gap: without this, an operator
//! with DB write access could rewrite past action receipts and nobody outside
//! the box would know.
//!
//! ## Anchoring procedure
//!
//! 1. Every `SAURON_ACTION_ANCHOR_INTERVAL_SECS` (default 600 s = 10 min):
//!    - Select all `agent_action_receipts` rows newer than the last anchor.
//!    - If empty, skip.
//!    - Compute `leaf_i = SHA256(receipt_id || action_hash || created_at)`.
//!    - Build a binary merkle tree (rs_merkle / sha256). Root = `batch_root`.
//!    - Persist a row in `agent_action_anchors` with the batch range.
//!    - Submit `batch_root` to Bitcoin via `bitcoin_anchor` (OTS calendar) AND
//!      Solana via `solana_anchor` (Memo Program). Record both receipt IDs.
//!
//! ## External verification
//!
//! Any auditor with a copy of an `agent_action_receipts` row can:
//!   - Recompute `leaf` from (receipt_id, action_hash, created_at).
//!   - Fetch the merkle path from `/admin/anchor/agent-actions/proof?receipt_id=…`
//!     and re-derive the root.
//!   - Look up the OTS proof in `bitcoin_merkle_anchors` and run `ots verify`.
//!   - Look up the Solana signature in `solana_merkle_anchors` and run
//!     `solana getTransaction <sig>`.
//!
//! This double-anchor design means: an attacker who rewrites the SQLite file
//! must ALSO compromise the Bitcoin and Solana chains to hide the tampering.
//! That's not a realistic adversary.

use rs_merkle::{algorithms::Sha256 as MerkleSha256, MerkleTree};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ajwt_support::random_hex_32;
use crate::state::ServerState;

const DEFAULT_INTERVAL_SECS: u64 = 600;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Compute the leaf hash for a single action receipt.
///
/// `leaf = SHA256(receipt_id || '|' || action_hash || '|' || created_at_ascii)`
///
/// All three components are append-only so the leaf is deterministic forever.
fn leaf_hash(receipt_id: &str, action_hash: &str, created_at: i64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(receipt_id.as_bytes());
    h.update(b"|");
    h.update(action_hash.as_bytes());
    h.update(b"|");
    h.update(created_at.to_string().as_bytes());
    h.finalize().into()
}

/// Trigger one anchor batch. Returns the new anchor row's id, or `None` if
/// there were no new receipts since the last anchor.
pub async fn anchor_pending_actions(
    state: &Arc<RwLock<ServerState>>,
) -> Result<Option<String>, String> {
    // 1. Determine the high-water mark from the previous anchor batch.
    // Receipts are anchored in created_at order; we resume from the max
    // `to_created_at` we've already covered.
    let (last_to, last_receipt_id): (i64, String) = {
        let st = state.read().unwrap();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        conn.query_row(
            "SELECT to_created_at, to_receipt_id FROM agent_action_anchors
             ORDER BY to_created_at DESC LIMIT 1",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
        )
        .unwrap_or((0i64, String::new()))
    };

    // 2. Pull all receipts after that watermark, ordered.
    let receipts: Vec<(String, String, i64)> = {
        let st = state.read().unwrap();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT receipt_id, action_hash, created_at
                 FROM agent_action_receipts
                 WHERE created_at > ?1 OR (created_at = ?1 AND receipt_id > ?2)
                 ORDER BY created_at ASC, receipt_id ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![last_to, last_receipt_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        rows.flatten().collect()
    };

    if receipts.is_empty() {
        return Ok(None);
    }

    // 3. Build the merkle tree over leaves.
    let leaves: Vec<[u8; 32]> = receipts
        .iter()
        .map(|(rid, ah, ts)| leaf_hash(rid, ah, *ts))
        .collect();
    let tree = MerkleTree::<MerkleSha256>::from_leaves(&leaves);
    let root: [u8; 32] = tree.root().ok_or("empty merkle tree (unreachable)")?;
    let batch_root_hex = hex::encode(root);

    let from_receipt_id = receipts.first().unwrap().0.clone();
    let to_receipt_id = receipts.last().unwrap().0.clone();
    let from_created_at = receipts.first().unwrap().2;
    let to_created_at = receipts.last().unwrap().2;
    let n_actions = receipts.len() as i64;

    let anchor_id = format!("aaa_{}", random_hex_32());

    // 4. Persist the batch row first (so the on-chain anchors can reference it).
    {
        let st = state.read().unwrap();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO agent_action_anchors
             (anchor_id, batch_root_hex, n_actions, from_receipt_id, to_receipt_id,
              from_created_at, to_created_at, btc_anchor_id, sol_anchor_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', '', ?8)",
            params![
                anchor_id,
                batch_root_hex,
                n_actions,
                from_receipt_id,
                to_receipt_id,
                from_created_at,
                to_created_at,
                now_secs(),
            ],
        )
        .map_err(|e| format!("DB insert agent_action_anchors: {e}"))?;
    }

    // 5. Fire BOTH on-chain anchors in parallel; collect receipt ids.
    let bitcoin_anchor = state.read().unwrap().bitcoin_anchor.clone();
    let solana_anchor = state.read().unwrap().solana_anchor.clone();
    let db = state.read().unwrap().db.clone();

    let btc_handle = if let Some(svc) = bitcoin_anchor {
        let db = Arc::clone(&db);
        let r = root;
        Some(tokio::spawn(async move { svc.publish_new_root(&db, r).await }))
    } else {
        None
    };
    let sol_handle = if let Some(svc) = solana_anchor {
        let db = Arc::clone(&db);
        let r = root;
        Some(tokio::spawn(async move { svc.publish_root(&db, r).await }))
    } else {
        None
    };

    let mut btc_id = String::new();
    let mut sol_id = String::new();
    if let Some(h) = btc_handle {
        match h.await {
            Ok(Ok(receipt)) => {
                btc_id = receipt.anchor_id;
                tracing::info!(
                    target: "sauron::action_anchor",
                    anchor_id = %anchor_id,
                    btc_anchor_id = %btc_id,
                    n_actions = n_actions,
                    "agent action root anchored on Bitcoin"
                );
            }
            Ok(Err(e)) => tracing::warn!(target: "sauron::action_anchor", error = %e, "BTC anchor failed (non-fatal)"),
            Err(e) => tracing::warn!(target: "sauron::action_anchor", error = %e, "BTC anchor task join error"),
        }
    }
    if let Some(h) = sol_handle {
        match h.await {
            Ok(Ok(receipt)) => {
                sol_id = receipt.anchor_id;
                tracing::info!(
                    target: "sauron::action_anchor",
                    anchor_id = %anchor_id,
                    sol_anchor_id = %sol_id,
                    sol_signature = %receipt.signature,
                    n_actions = n_actions,
                    "agent action root anchored on Solana"
                );
            }
            Ok(Err(e)) => tracing::warn!(target: "sauron::action_anchor", error = %e, "Solana anchor failed (non-fatal)"),
            Err(e) => tracing::warn!(target: "sauron::action_anchor", error = %e, "Solana anchor task join error"),
        }
    }

    // 6. Update the batch row with the on-chain anchor ids.
    {
        let st = state.read().unwrap();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "UPDATE agent_action_anchors SET btc_anchor_id = ?1, sol_anchor_id = ?2 WHERE anchor_id = ?3",
            params![btc_id, sol_id, anchor_id],
        )
        .ok();
    }

    Ok(Some(anchor_id))
}

/// Spawn a background task that calls `anchor_pending_actions` every interval.
pub fn spawn_action_anchor_task(state: Arc<RwLock<ServerState>>) {
    let interval_secs: u64 = std::env::var("SAURON_ACTION_ANCHOR_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS)
        .clamp(60, 86_400);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.tick().await; // skip initial fire
        loop {
            ticker.tick().await;
            match anchor_pending_actions(&state).await {
                Ok(Some(id)) => tracing::debug!(target: "sauron::action_anchor", anchor_id = %id, "batch anchored"),
                Ok(None) => tracing::trace!(target: "sauron::action_anchor", "no new actions to anchor"),
                Err(e) => tracing::warn!(target: "sauron::action_anchor", error = %e, "anchor batch failed"),
            }
        }
    });
}

/// Build a merkle inclusion proof for a specific receipt within its anchor batch.
/// Returns `(batch_root_hex, leaf_index, proof_hashes_hex, btc_anchor_id, sol_anchor_id)`.
pub fn proof_for_receipt(
    state: &Arc<RwLock<ServerState>>,
    receipt_id: &str,
) -> Result<Option<serde_json::Value>, String> {
    // 1. Find which batch covers this receipt.
    //
    // Receipt IDs are random hex; lexicographic ordering is meaningless.
    // The batch is identified by the (from_created_at, to_created_at) range,
    // and we cross-check the receipt actually exists with a created_at in that
    // window. The composite ordering used at anchor time was
    // `(created_at ASC, receipt_id ASC)`, so a tie on created_at is broken
    // deterministically by lexicographic receipt_id — but inclusion in the
    // batch is determined by created_at first.
    let receipt_created_at: i64 = {
        let st = state.read().unwrap();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        match conn.query_row(
            "SELECT created_at FROM agent_action_receipts WHERE receipt_id = ?1",
            params![receipt_id],
            |r| r.get::<_, i64>(0),
        ) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        }
    };

    let batch: Option<(String, String, i64, i64, String, String)> = {
        let st = state.read().unwrap();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        conn.query_row(
            "SELECT anchor_id, batch_root_hex, from_created_at, to_created_at, btc_anchor_id, sol_anchor_id
             FROM agent_action_anchors
             WHERE from_created_at <= ?1 AND to_created_at >= ?1
             ORDER BY created_at ASC LIMIT 1",
            params![receipt_created_at],
            |r| Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            )),
        )
        .ok()
    };

    let (anchor_id, batch_root_hex, from_ts, to_ts, btc, sol) = match batch {
        Some(b) => b,
        None => return Ok(None),
    };

    // 2. Re-fetch the same ordered receipt set, build the same tree, ask for the proof.
    let receipts: Vec<(String, String, i64)> = {
        let st = state.read().unwrap();
        let conn = st.db.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT receipt_id, action_hash, created_at
                 FROM agent_action_receipts
                 WHERE created_at >= ?1 AND created_at <= ?2
                 ORDER BY created_at ASC, receipt_id ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![from_ts, to_ts], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        rows.flatten().collect()
    };

    let leaves: Vec<[u8; 32]> = receipts
        .iter()
        .map(|(rid, ah, ts)| leaf_hash(rid, ah, *ts))
        .collect();
    let leaf_index = receipts
        .iter()
        .position(|(rid, _, _)| rid == receipt_id)
        .ok_or("receipt not in batch (DB drift?)")?;

    let tree = MerkleTree::<MerkleSha256>::from_leaves(&leaves);
    let proof = tree.proof(&[leaf_index]);
    let proof_hashes: Vec<String> = proof
        .proof_hashes()
        .iter()
        .map(hex::encode)
        .collect();

    Ok(Some(serde_json::json!({
        "anchor_id": anchor_id,
        "batch_root_hex": batch_root_hex,
        "leaf_index": leaf_index,
        "leaf_hex": hex::encode(leaves[leaf_index]),
        "proof_hashes_hex": proof_hashes,
        "tree_size": leaves.len(),
        "btc_anchor_id": btc,
        "sol_anchor_id": sol,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_hash_is_deterministic() {
        let a = leaf_hash("rcp_abc", "deadbeef", 12345);
        let b = leaf_hash("rcp_abc", "deadbeef", 12345);
        assert_eq!(a, b);
    }

    #[test]
    fn leaf_hash_changes_with_any_field() {
        let base = leaf_hash("rcp_abc", "deadbeef", 12345);
        assert_ne!(base, leaf_hash("rcp_abd", "deadbeef", 12345));
        assert_ne!(base, leaf_hash("rcp_abc", "deadbeee", 12345));
        assert_ne!(base, leaf_hash("rcp_abc", "deadbeef", 12346));
    }
}

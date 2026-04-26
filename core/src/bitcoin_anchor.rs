use rusqlite::params;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ajwt_support::random_hex_32;
use crate::db::DbHandle;

#[derive(Clone)]
pub struct BitcoinAnchorService {
    provider: String,
    network: String,
}

pub struct BitcoinAnchorReceipt {
    pub anchor_id: String,
    pub txid: String,
    pub op_return_hex: String,
    pub network: String,
    pub no_real_money: bool,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    hex::encode(h.finalize())
}

fn op_return_for_merkle_root(root: &[u8; 32]) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.push(0x6a); // OP_RETURN
    payload.push(0x20); // push 32 bytes
    payload.extend_from_slice(root);
    hex::encode(payload)
}

impl BitcoinAnchorService {
    pub fn from_env() -> Option<Self> {
        let provider = std::env::var("SAURON_BITCOIN_ANCHOR_PROVIDER")
            .unwrap_or_else(|_| "mock".to_string())
            .trim()
            .to_ascii_lowercase();
        if provider.is_empty() || provider == "disabled" || provider == "none" {
            return None;
        }
        let network = std::env::var("SAURON_BITCOIN_NETWORK")
            .unwrap_or_else(|_| "regtest-mock".to_string())
            .trim()
            .to_ascii_lowercase();
        if provider != "mock" {
            eprintln!(
                "[BITCOIN] Provider '{}' requested but only mock is implemented; anchoring disabled.",
                provider
            );
            return None;
        }
        Some(Self { provider, network })
    }

    pub async fn publish_new_root(
        &self,
        db: &DbHandle,
        merkle_root: [u8; 32],
    ) -> Result<BitcoinAnchorReceipt, String> {
        if self.provider != "mock" {
            return Err("Only SAURON_BITCOIN_ANCHOR_PROVIDER=mock is implemented".into());
        }

        let now = now_secs();
        let root_hex = hex::encode(merkle_root);
        let op_return_hex = op_return_for_merkle_root(&merkle_root);
        let anchor_id = format!("btca_{}", random_hex_32());
        let txid = sha256_hex(&[
            b"SAURON_BITCOIN_ANCHOR|",
            anchor_id.as_bytes(),
            b"|",
            root_hex.as_bytes(),
            b"|",
            now.to_string().as_bytes(),
        ]);

        let conn = db.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO bitcoin_merkle_anchors
             (anchor_id, merkle_root_hex, provider, network, op_return_hex, txid, broadcast, no_real_money, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 1, ?7)",
            params![
                anchor_id,
                root_hex,
                self.provider,
                self.network,
                op_return_hex,
                txid,
                now,
            ],
        )
        .map_err(|e| format!("DB error: {e}"))?;

        Ok(BitcoinAnchorReceipt {
            anchor_id,
            txid,
            op_return_hex,
            network: self.network.clone(),
            no_real_money: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn op_return_payload_contains_exact_merkle_root() {
        let root = [7u8; 32];
        let op_return = op_return_for_merkle_root(&root);
        assert_eq!(op_return, format!("6a20{}", hex::encode(root)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mock_bitcoin_anchor_records_no_cost_receipt() {
        let _guard = env_lock().lock().unwrap();
        let db_path = std::env::temp_dir().join(format!("sauron-btc-anchor-{}.db", random_hex_32()));
        std::env::set_var("DATABASE_PATH", db_path.to_string_lossy().to_string());
        std::env::set_var("SAURON_BITCOIN_ANCHOR_PROVIDER", "mock");
        std::env::set_var("SAURON_BITCOIN_NETWORK", "regtest-mock");

        let db_handle = db::open_db();
        let service = BitcoinAnchorService::from_env().unwrap();
        let root = [42u8; 32];
        let receipt = service.publish_new_root(&db_handle, root).await.unwrap();

        assert!(receipt.anchor_id.starts_with("btca_"));
        assert_eq!(receipt.op_return_hex, format!("6a20{}", hex::encode(root)));
        assert_eq!(receipt.network, "regtest-mock");
        assert!(receipt.no_real_money);

        let conn = db_handle.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM bitcoin_merkle_anchors WHERE anchor_id = ?1 AND no_real_money = 1",
                params![receipt.anchor_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        drop(conn);
        drop(db_handle);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    }
}

use std::path::PathBuf;

use base64::Engine;
use risc0_zkvm::{sha::Digest, InnerReceipt, Receipt};
use sauron_transparent_types::{
    TransparentJournal, TransparentStatement, ACTION_POLICY_PROGRAM_ID, JOURNAL_PROTOCOL,
    STATS_PROGRAM_ID,
};

const MAX_INPUT_BYTES: u64 = 25 * 1024 * 1024;
const MAX_RECEIPT_JSON_BYTES: usize = 18 * 1024 * 1024;
const STATS_IMAGE_ID_HEX: &str = "dd4bf48ed1cc4d62d51b153075a438048d03e832c3a8d50fdf4db9c0240a8060";
const ACTION_POLICY_IMAGE_ID_HEX: &str =
    "4e7ad7997c31f4a4a9e870e40f5a059306803fca724e14d2e3fa7bf90cdd9aa5";

fn pinned_image_id(program_id: &str) -> Result<Digest, Box<dyn std::error::Error>> {
    let image_hex = match program_id {
        STATS_PROGRAM_ID => STATS_IMAGE_ID_HEX,
        ACTION_POLICY_PROGRAM_ID => ACTION_POLICY_IMAGE_ID_HEX,
        _ => return Err("program_id is not a published SauronID guest".into()),
    };
    let bytes = hex::decode(image_hex)?;
    Ok(Digest::try_from(bytes.as_slice())?)
}

fn require_native_stark(receipt: &Receipt) -> Result<(), Box<dyn std::error::Error>> {
    match &receipt.inner {
        InnerReceipt::Succinct(_) => Ok(()),
        InnerReceipt::Composite(_) => Err("Composite receipt rejected".into()),
        InnerReceipt::Groth16(_) => Err("Groth16 receipt rejected".into()),
        InnerReceipt::Fake(_) => Err("fake receipt rejected".into()),
        _ => Err("unknown receipt type rejected pending review".into()),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: sauron-transparent-verify <proof-output.json>")?;
    if std::fs::metadata(&path)?.len() > MAX_INPUT_BYTES {
        return Err("proof file exceeds verifier size limit".into());
    }
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let program_id = value
        .get("program_id")
        .and_then(|v| v.as_str())
        .ok_or("proof output has no program_id")?;
    let image_id = pinned_image_id(program_id)?;
    let encoded = value
        .get("receipt_b64")
        .and_then(|v| v.as_str())
        .ok_or("proof output has no receipt_b64")?;
    let receipt_json = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    if receipt_json.len() > MAX_RECEIPT_JSON_BYTES {
        return Err("decoded receipt exceeds verifier size limit".into());
    }
    let receipt: Receipt = serde_json::from_slice(&receipt_json)?;
    require_native_stark(&receipt)?;
    receipt
        .verify(image_id)
        .map_err(|e| std::io::Error::other(format!("receipt verification failed: {e:?}")))?;
    let journal: TransparentJournal = receipt.journal.decode()?;
    if journal.protocol != JOURNAL_PROTOCOL || journal.program_id != program_id {
        return Err("verified journal has the wrong protocol or program ID".into());
    }
    match (&journal.statement, program_id) {
        (TransparentStatement::Stats { .. }, STATS_PROGRAM_ID)
        | (TransparentStatement::ActionPolicy { .. }, ACTION_POLICY_PROGRAM_ID) => {}
        _ => return Err("verified journal statement does not match its program".into()),
    }
    println!("{}", serde_json::to_string_pretty(&journal)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_ids_are_exact_digests() {
        assert!(pinned_image_id(STATS_PROGRAM_ID).is_ok());
        assert!(pinned_image_id(ACTION_POLICY_PROGRAM_ID).is_ok());
        assert!(pinned_image_id("attacker-program").is_err());
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../image-ids.json")).unwrap();
        assert_eq!(
            manifest["programs"][STATS_PROGRAM_ID],
            serde_json::Value::String(STATS_IMAGE_ID_HEX.into())
        );
        assert_eq!(
            manifest["programs"][ACTION_POLICY_PROGRAM_ID],
            serde_json::Value::String(ACTION_POLICY_IMAGE_ID_HEX.into())
        );
    }

    #[test]
    fn fake_and_groth16_receipts_fail_closed() {
        use risc0_zkvm::{FakeReceipt, Groth16Receipt, MaybePruned, ReceiptClaim};

        let claim: MaybePruned<ReceiptClaim> = MaybePruned::Pruned(Digest::ZERO);
        let fake = Receipt::new(
            InnerReceipt::Fake(FakeReceipt::new(claim.clone())),
            Vec::new(),
        );
        assert!(require_native_stark(&fake).is_err());

        let groth16 = Receipt::new(
            InnerReceipt::Groth16(Groth16Receipt::new(Vec::new(), claim, Digest::ZERO)),
            Vec::new(),
        );
        assert!(require_native_stark(&groth16).is_err());
    }
}

use std::path::PathBuf;

use base64::Engine;
use risc0_zkvm::{sha::Digest, InnerReceipt, Receipt};
use sauron_transparent_methods::{SAURON_ACTION_POLICY_GUEST_ID, SAURON_STATS_GUEST_ID};
use sauron_transparent_types::{
    TransparentJournal, ACTION_POLICY_PROGRAM_ID, JOURNAL_PROTOCOL, STATS_PROGRAM_ID,
};

const MAX_INPUT_BYTES: u64 = 128 * 1024 * 1024;

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
    let image_id = match program_id {
        STATS_PROGRAM_ID => Digest::from(SAURON_STATS_GUEST_ID),
        ACTION_POLICY_PROGRAM_ID => Digest::from(SAURON_ACTION_POLICY_GUEST_ID),
        _ => return Err("program_id is not a published SauronID guest".into()),
    };
    let encoded = value
        .get("receipt_b64")
        .and_then(|v| v.as_str())
        .ok_or("proof output has no receipt_b64")?;
    let receipt_json = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    if receipt_json.len() as u64 > MAX_INPUT_BYTES {
        return Err("decoded receipt exceeds verifier size limit".into());
    }
    let receipt: Receipt = serde_json::from_slice(&receipt_json)?;
    match &receipt.inner {
        InnerReceipt::Composite(_) | InnerReceipt::Succinct(_) => {}
        InnerReceipt::Groth16(_) => return Err("Groth16 receipt rejected".into()),
        InnerReceipt::Fake(_) => return Err("fake receipt rejected".into()),
        _ => return Err("unknown receipt type rejected pending review".into()),
    }
    receipt.verify(image_id)?;
    let journal: TransparentJournal = receipt.journal.decode()?;
    if journal.protocol != JOURNAL_PROTOCOL || journal.program_id != program_id {
        return Err("verified journal has the wrong protocol or program ID".into());
    }
    println!("{}", serde_json::to_string_pretty(&journal)?);
    Ok(())
}

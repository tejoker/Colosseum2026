use std::path::PathBuf;

use base64::Engine;
use risc0_zkvm::{default_prover, sha::Digest, ExecutorEnv, InnerReceipt, ProverOpts};
use sauron_transparent_methods::{
    SAURON_ACTION_POLICY_GUEST_ELF, SAURON_ACTION_POLICY_GUEST_ID, SAURON_STATS_GUEST_ELF,
    SAURON_STATS_GUEST_ID,
};
use sauron_transparent_types::{
    ActionPolicyProofInput, StatsProofInput, TransparentJournal, ACTION_POLICY_PROGRAM_ID,
    STATS_PROGRAM_ID,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.as_slice() == ["--image-ids"] {
        let stats = Digest::from(SAURON_STATS_GUEST_ID);
        let action = Digest::from(SAURON_ACTION_POLICY_GUEST_ID);
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                STATS_PROGRAM_ID: hex::encode(stats.as_bytes()),
                ACTION_POLICY_PROGRAM_ID: hex::encode(action.as_bytes()),
            }))?
        );
        return Ok(());
    }
    let (kind, input_path, self_test) = match args.as_slice() {
        [path] => ("stats", PathBuf::from(path), false),
        [kind, path] if kind == "--self-test" => ("stats", PathBuf::from(path), true),
        [kind, path] if kind == "--self-test-action" => {
            ("--action-policy", PathBuf::from(path), true)
        }
        [kind, path] if kind == "--stats" || kind == "--action-policy" => {
            (
                kind.to_str().ok_or("mode is not UTF-8")?,
                PathBuf::from(path),
                false,
            )
        }
        _ => return Err("usage: sauron-transparent-prover --image-ids | --self-test <stats-input.json> | --self-test-action <action-input.json> | [--stats|--action-policy] <private-input.json>".into()),
    };
    let private_input = std::fs::read(&input_path)?;
    let (info, image_id, program_id) = if kind == "--action-policy" {
        let input: ActionPolicyProofInput = serde_json::from_slice(&private_input)?;
        let env = ExecutorEnv::builder().write(&input)?.build()?;
        let info = default_prover().prove_with_opts(
            env,
            SAURON_ACTION_POLICY_GUEST_ELF,
            &ProverOpts::succinct(),
        )?;
        (
            info,
            Digest::from(SAURON_ACTION_POLICY_GUEST_ID),
            ACTION_POLICY_PROGRAM_ID,
        )
    } else {
        let input: StatsProofInput = serde_json::from_slice(&private_input)?;
        let env = ExecutorEnv::builder().write(&input)?.build()?;
        let info = default_prover().prove_with_opts(
            env,
            SAURON_STATS_GUEST_ELF,
            &ProverOpts::succinct(),
        )?;
        (info, Digest::from(SAURON_STATS_GUEST_ID), STATS_PROGRAM_ID)
    };
    let journal: TransparentJournal = info.receipt.journal.decode()?;
    if self_test {
        if !matches!(&info.receipt.inner, InnerReceipt::Succinct(_)) {
            return Err("self-test prover did not produce a native Succinct STARK receipt".into());
        }
        info.receipt.verify(image_id)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "verified": true,
                "receipt_type": "succinct_stark",
                "program_id": program_id,
                "image_id_hex": hex::encode(image_id.as_bytes()),
                "journal": journal,
            }))?
        );
        return Ok(());
    }
    let receipt_json = serde_json::to_vec(&info.receipt)?;
    let output = serde_json::json!({
        "program_id": program_id,
        "image_id_hex": hex::encode(image_id.as_bytes()),
        "receipt_b64": base64::engine::general_purpose::STANDARD.encode(receipt_json),
        "journal": journal,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

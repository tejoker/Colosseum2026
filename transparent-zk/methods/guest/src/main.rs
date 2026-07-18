#![no_main]

use risc0_zkvm::guest::env;
use sauron_transparent_types::{
    AgentActionEnvelope, AnchoredReceiptV2, StatsProofInput, TransparentJournal,
    TransparentStatement, JOURNAL_PROTOCOL, STATS_PROGRAM_ID,
};
use sha2::{Digest, Sha256};

risc0_zkvm::guest::entry!(main);

fn push_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("canonical field length exceeds u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
}

fn canonical_fields(domain: &str, fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    push_len_prefixed(&mut out, domain.as_bytes());
    for (name, value) in fields {
        push_len_prefixed(&mut out, name.as_bytes());
        push_len_prefixed(&mut out, value.as_bytes());
    }
    out
}

fn action_hash(envelope: &AgentActionEnvelope) -> String {
    // Serde preserves struct declaration order.  The type exactly mirrors the
    // core's fixed-order canonical JSON and serde_json uses the same escaping.
    let encoded = serde_json::to_vec(envelope).expect("action envelope encoding");
    hex::encode(Sha256::digest(encoded))
}

fn receipt_leaf(receipt: &AnchoredReceiptV2) -> [u8; 32] {
    let created_at = receipt.created_at.to_string();
    Sha256::digest(canonical_fields(
        "sauron.action-anchor-leaf.v2",
        &[
            ("tenant_id", &receipt.tenant_id),
            ("receipt_id", &receipt.receipt_id),
            ("action_hash", &receipt.action_hash),
            ("agent_id", &receipt.agent_id),
            ("ring_key_image_hex", &receipt.ring_key_image_hex),
            ("policy_version", &receipt.policy_version),
            ("ajwt_jti", &receipt.ajwt_jti),
            ("pop_jkt", &receipt.pop_jkt),
            ("status", &receipt.status),
            ("signature", &receipt.signature),
            ("created_at", &created_at),
            ("ring_id", &receipt.ring_id),
            ("config_digest", &receipt.config_digest),
        ],
    ))
    .into()
}

fn merkle_root(mut nodes: Vec<[u8; 32]>) -> [u8; 32] {
    assert!(!nodes.is_empty(), "empty receipt set");
    while nodes.len() > 1 {
        let mut parents = Vec::with_capacity((nodes.len() + 1) / 2);
        for pair in nodes.chunks(2) {
            if pair.len() == 1 {
                // rs_merkle propagates an unpaired left node unchanged.
                parents.push(pair[0]);
            } else {
                let mut bytes = [0u8; 64];
                bytes[..32].copy_from_slice(&pair[0]);
                bytes[32..].copy_from_slice(&pair[1]);
                parents.push(Sha256::digest(bytes).into());
            }
        }
        nodes = parents;
    }
    nodes[0]
}

fn is_success(status: &str) -> bool {
    matches!(
        status.to_ascii_lowercase().as_str(),
        "accepted" | "authorized" | "ok" | "success" | "verified"
    )
}

fn computed_metric(input: &StatsProofInput) -> i64 {
    let n = i64::try_from(input.records.len()).expect("receipt count exceeds i64");
    match input.metric_id.as_str() {
        "success_rate" => {
            let successes = input
                .records
                .iter()
                .filter(|r| is_success(&r.receipt.status))
                .count() as i64;
            successes.checked_mul(1000).expect("success sum overflow") / n
        }
        "error_rate" => {
            let errors = input
                .records
                .iter()
                .filter(|r| !is_success(&r.receipt.status))
                .count() as i64;
            errors.checked_mul(1000).expect("error sum overflow") / n
        }
        "tool_call_count" => {
            let calls = input
                .records
                .iter()
                .filter(|r| !r.envelope.action.trim().is_empty())
                .count() as i64;
            calls.checked_mul(1000).expect("call count overflow")
        }
        "cost_total" => input.records.iter().fold(0i64, |total, r| {
            assert!(
                r.envelope.currency.eq_ignore_ascii_case("USD"),
                "cost_total only accepts USD receipts; currency conversion is not hidden inside the proof"
            );
            assert!(r.envelope.amount_minor >= 0, "negative cost receipt");
            total
                .checked_add(
                    r.envelope
                        .amount_minor
                        .checked_mul(10)
                        .expect("milli-USD conversion overflow"),
                )
                .expect("cost total overflow")
        }),
        _ => panic!("metric is not implemented by this reviewed guest"),
    }
}

fn main() {
    let input: StatsProofInput = env::read();
    assert!(!input.tenant_id.trim().is_empty(), "tenant_id is empty");
    assert!(!input.checkpoint_id.trim().is_empty(), "checkpoint_id is empty");
    assert!(!input.action_anchor_id.trim().is_empty(), "action anchor is empty");
    assert!(input.period_start <= input.period_end, "invalid period");
    assert!(!input.records.is_empty(), "empty receipt set");
    assert!(input.records.len() <= 10_000, "receipt cap exceeded");

    let expected_root = input
        .expected_merkle_root
        .trim()
        .trim_start_matches("0x")
        .to_ascii_lowercase();
    assert_eq!(expected_root.len(), 64, "root must be 32-byte hex");

    let mut leaves = Vec::with_capacity(input.records.len());
    for record in &input.records {
        assert_eq!(record.receipt.tenant_id, input.tenant_id, "tenant mismatch");
        assert_eq!(record.receipt.agent_id, record.envelope.agent_id, "agent mismatch");
        assert_eq!(record.receipt.ajwt_jti, record.envelope.ajwt_jti, "JTI mismatch");
        assert_eq!(record.receipt.action_hash, action_hash(&record.envelope), "action preimage mismatch");
        assert!(
            record.receipt.created_at >= input.period_start
                && record.receipt.created_at <= input.period_end,
            "receipt outside reporting period"
        );
        if let Some(expected_agent) = &input.agent_id_or_none {
            assert_eq!(&record.receipt.agent_id, expected_agent, "agent scope mismatch");
        }
        // Stats checkpoints accept only ordinary signed action receipts.  This
        // also prevents an opaque/synthetic egress row from entering a witness.
        assert!(!record.receipt.ring_key_image_hex.is_empty(), "missing ring identity");
        assert!(!record.receipt.signature.is_empty(), "unsigned receipt");
        assert!(record.receipt.ring_id.is_empty(), "anonymous receipt uses a different preimage");
        assert!(record.receipt.config_digest.is_empty(), "unexpected anonymous config digest");
        leaves.push(receipt_leaf(&record.receipt));
    }

    let actual_root = hex::encode(merkle_root(leaves));
    assert_eq!(actual_root, expected_root, "complete batch Merkle root mismatch");
    let claimed_value = computed_metric(&input);
    let journal = TransparentJournal {
        protocol: JOURNAL_PROTOCOL.into(),
        program_id: STATS_PROGRAM_ID.into(),
        statement: TransparentStatement::Stats {
            tenant_id: input.tenant_id,
            checkpoint_id: input.checkpoint_id,
            action_anchor_id: input.action_anchor_id,
            merkle_root: actual_root,
            tree_size: input.records.len() as u64,
            agent_id_or_none: input.agent_id_or_none,
            metric_id: input.metric_id,
            claimed_value,
            period_start: input.period_start,
            period_end: input.period_end,
        },
    };
    env::commit(&journal);
}


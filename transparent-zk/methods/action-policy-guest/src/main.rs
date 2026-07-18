#![no_main]

use risc0_zkvm::guest::env;
use sauron_transparent_types::{
    ActionPolicyProofInput, ActionPredicate, AgentActionEnvelope, AnchoredReceiptV2,
    TransparentJournal, TransparentStatement, ACTION_POLICY_PROGRAM_ID, JOURNAL_PROTOCOL,
};
use sha2::{Digest, Sha256};

risc0_zkvm::guest::entry!(main);

fn push(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u32::try_from(value.len()).expect("field too long").to_be_bytes());
    out.extend_from_slice(value);
}

fn canonical_fields(domain: &str, fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    push(&mut out, domain.as_bytes());
    for (name, value) in fields {
        push(&mut out, name.as_bytes());
        push(&mut out, value.as_bytes());
    }
    out
}

fn action_hash(envelope: &AgentActionEnvelope) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(envelope).expect("envelope encoding"),
    ))
}

fn receipt_leaf(r: &AnchoredReceiptV2) -> [u8; 32] {
    let created_at = r.created_at.to_string();
    Sha256::digest(canonical_fields(
        "sauron.action-anchor-leaf.v2",
        &[
            ("tenant_id", &r.tenant_id),
            ("receipt_id", &r.receipt_id),
            ("action_hash", &r.action_hash),
            ("agent_id", &r.agent_id),
            ("ring_key_image_hex", &r.ring_key_image_hex),
            ("policy_version", &r.policy_version),
            ("ajwt_jti", &r.ajwt_jti),
            ("pop_jkt", &r.pop_jkt),
            ("status", &r.status),
            ("signature", &r.signature),
            ("created_at", &created_at),
            ("ring_id", &r.ring_id),
            ("config_digest", &r.config_digest),
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

fn validate_predicate(input: &ActionPolicyProofInput) {
    match &input.predicate {
        ActionPredicate::AllActionsIn { allowed_actions } => {
            assert!(!allowed_actions.is_empty(), "empty action allowlist");
            let mut canonical = allowed_actions.clone();
            canonical.sort();
            canonical.dedup();
            assert_eq!(&canonical, allowed_actions, "allowlist must be sorted and unique");
            assert!(input.records.iter().all(|r| {
                allowed_actions.binary_search(&r.envelope.action).is_ok()
            }), "receipt action outside allowlist");
        }
        ActionPredicate::TotalAmountAtMost { currency, maximum_minor } => {
            assert!(*maximum_minor >= 0, "negative maximum");
            let total = input.records.iter().fold(0i64, |sum, r| {
                assert_eq!(&r.envelope.currency, currency, "currency mismatch");
                assert!(r.envelope.amount_minor >= 0, "negative amount");
                sum.checked_add(r.envelope.amount_minor).expect("amount overflow")
            });
            assert!(total <= *maximum_minor, "amount bound exceeded");
        }
        ActionPredicate::CountInRange { minimum, maximum } => {
            assert!(minimum <= maximum, "invalid count range");
            let count = input.records.len() as u64;
            assert!(count >= *minimum && count <= *maximum, "count outside range");
        }
        ActionPredicate::NoAction { forbidden_action } => assert!(
            input.records.iter().all(|r| r.envelope.action != *forbidden_action),
            "forbidden action present"
        ),
        ActionPredicate::ContainsAction { required_action } => assert!(
            input.records.iter().any(|r| r.envelope.action == *required_action),
            "required action absent"
        ),
        ActionPredicate::TimeWindow { not_before, not_after } => {
            assert!(not_before <= not_after, "invalid time window");
            assert!(input.records.iter().all(|r| {
                r.receipt.created_at >= *not_before && r.receipt.created_at <= *not_after
            }), "receipt outside time window");
        }
    }
}

fn main() {
    let input: ActionPolicyProofInput = env::read();
    assert!(!input.tenant_id.trim().is_empty(), "tenant is empty");
    assert!(!input.checkpoint_id.trim().is_empty(), "checkpoint is empty");
    assert!(!input.action_anchor_id.trim().is_empty(), "anchor is empty");
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
        if let Some(expected_agent) = &input.agent_id_or_none {
            assert_eq!(&record.receipt.agent_id, expected_agent, "agent scope mismatch");
        }
        assert!(!record.receipt.ring_key_image_hex.is_empty(), "missing ring identity");
        assert!(!record.receipt.signature.is_empty(), "unsigned receipt");
        assert!(record.receipt.ring_id.is_empty(), "anonymous receipt is unsupported");
        assert!(record.receipt.config_digest.is_empty(), "anonymous config is unsupported");
        leaves.push(receipt_leaf(&record.receipt));
    }
    let actual_root = hex::encode(merkle_root(leaves));
    assert_eq!(actual_root, expected_root, "complete batch root mismatch");
    validate_predicate(&input);

    let predicate_parameters_sha256 = hex::encode(Sha256::digest(
        serde_json::to_vec(&input.predicate).expect("predicate encoding"),
    ));
    let journal = TransparentJournal {
        protocol: JOURNAL_PROTOCOL.into(),
        program_id: ACTION_POLICY_PROGRAM_ID.into(),
        statement: TransparentStatement::ActionPolicy {
            tenant_id: input.tenant_id,
            checkpoint_id: input.checkpoint_id,
            action_anchor_id: input.action_anchor_id,
            merkle_root: actual_root,
            tree_size: input.records.len() as u64,
            predicate_id: input.predicate.id().into(),
            predicate_parameters_sha256,
        },
    };
    env::commit(&journal);
}


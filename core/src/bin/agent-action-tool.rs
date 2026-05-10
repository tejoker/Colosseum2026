use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use sauron_core::{
    agent_action::{canonical_envelope_bytes, AgentActionChallengeResponse, AgentActionProof},
    identity::Identity,
    ring as leash_ring,
};
use serde_json::json;
use std::{env, fs, path::Path, process};

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("{}", message.as_ref());
    process::exit(1);
}

fn usage() -> ! {
    fail(
        "usage:\n  agent-action-tool keygen\n  agent-action-tool sign-challenge --secret-hex <hex> --challenge-json <json|@path|path>",
    )
}

fn point_from_hex(label: &str, value: &str) -> Result<RistrettoPoint, String> {
    let bytes = hex::decode(value).map_err(|_| format!("{label} must be hex"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{label} must be 32 bytes"))?;
    CompressedRistretto(arr)
        .decompress()
        .ok_or_else(|| format!("{label} is not a valid Ristretto point"))
}

fn read_challenge_json(arg: &str) -> Result<String, String> {
    if let Some(path) = arg.strip_prefix('@') {
        return fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"));
    }
    if Path::new(arg).is_file() {
        return fs::read_to_string(arg).map_err(|e| format!("failed to read {arg}: {e}"));
    }
    Ok(arg.to_string())
}

fn sign_challenge(args: &[String]) -> Result<serde_json::Value, String> {
    let mut secret_hex: Option<String> = None;
    let mut challenge_arg: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--secret-hex" => {
                i += 1;
                secret_hex = args.get(i).cloned();
            }
            "--challenge-json" => {
                i += 1;
                challenge_arg = args.get(i).cloned();
            }
            _ => return Err(format!("unknown argument: {}", args[i])),
        }
        i += 1;
    }

    let secret_hex = secret_hex.ok_or_else(|| "--secret-hex is required".to_string())?;
    let challenge_arg = challenge_arg.ok_or_else(|| "--challenge-json is required".to_string())?;
    let identity = Identity::from_secret_hex(&secret_hex)
        .ok_or_else(|| "secret_hex must be a canonical 32-byte scalar".to_string())?;
    let challenge_json = read_challenge_json(&challenge_arg)?;
    let challenge: AgentActionChallengeResponse = serde_json::from_str(&challenge_json)
        .map_err(|e| format!("challenge JSON invalid: {e}"))?;

    let ring_members: Vec<RistrettoPoint> = challenge
        .agent_ring_public_keys_hex
        .iter()
        .enumerate()
        .map(|(idx, pk)| point_from_hex(&format!("agent_ring_public_keys_hex[{idx}]"), pk))
        .collect::<Result<Vec<_>, _>>()?;
    if ring_members.is_empty() {
        return Err("challenge ring is empty".into());
    }
    let signer_point = ring_members.get(challenge.signer_index).ok_or_else(|| {
        format!(
            "signer_index {} is outside ring length {}",
            challenge.signer_index,
            ring_members.len()
        )
    })?;
    if signer_point != &identity.public {
        return Err("secret_hex does not match challenge signer_index public key".into());
    }
    if !challenge
        .signing_public_key_hex
        .eq_ignore_ascii_case(&identity.public_hex())
    {
        return Err("secret_hex does not match challenge signing_public_key_hex".into());
    }

    let msg = canonical_envelope_bytes(&challenge.envelope);
    let ring_signature = leash_ring::sign(&msg, &ring_members, &identity, challenge.signer_index);
    let proof = AgentActionProof {
        envelope: challenge.envelope,
        ring_signature,
    };
    serde_json::to_value(proof).map_err(|e| format!("failed to encode proof: {e}"))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let Some(cmd) = args.get(1).map(String::as_str) else {
        usage();
    };
    let output = match cmd {
        "keygen" => {
            if args.len() != 2 {
                usage();
            }
            let identity = Identity::random();
            Ok(json!({
                "public_key_hex": identity.public_hex(),
                "secret_hex": identity.secret_hex(),
                "ring_key_image_hex": identity.key_image_hex(),
            }))
        }
        "sign-challenge" => sign_challenge(&args[2..]),
        _ => {
            usage();
        }
    };
    match output {
        Ok(value) => println!("{}", serde_json::to_string(&value).unwrap()),
        Err(err) => fail(err),
    }
}

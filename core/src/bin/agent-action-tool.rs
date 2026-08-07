use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use sauron_core::{
    agent_action::{canonical_envelope_bytes, AgentActionChallengeResponse, AgentActionProof},
    crypto_protocol::{call_signature_payload, CallSignatureInput},
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
        "usage:\n  agent-action-tool keygen\n  agent-action-tool sign-challenge --secret-hex <hex> --challenge-json <json|@path|path>\n  agent-action-tool call-sig --pop-secret-b64u <b64u> --agent-id <id> --method <M> --target-uri <path> --body <json|@path|-> [--tenant <id>] [--audience <aud>] [--config-digest <d>] [--content-type <ct>]",
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

/// `--name value` lookup for the flag-style subcommands.
fn arg(args: &[String], name: &str) -> Result<String, String> {
    let needle = format!("--{name}");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == &needle {
            return it
                .next()
                .cloned()
                .ok_or_else(|| format!("--{name} needs a value"));
        }
    }
    Err(format!("--{name} is required"))
}

fn arg_opt(args: &[String], name: &str) -> Option<String> {
    arg(args, name).ok()
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
        "call-sig" => call_sig(&args[2..]),
        _ => {
            usage();
        }
    };
    match output {
        Ok(value) => println!("{}", serde_json::to_string(&value).unwrap()),
        Err(err) => fail(err),
    }
}

/// Emit the per-call signature headers for one request.
///
/// Shell e2e scripts had no way to produce these, so they posted unsigned to
/// routes that require a signature — which only stayed green because the old
/// per-route enforcement missed that path. Uses the same
/// `crypto_protocol::call_signature_payload` the server verifies with, so the
/// canonical bytes cannot drift between signer and verifier.
fn call_sig(args: &[String]) -> Result<serde_json::Value, String> {
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    let pop_secret = arg(args, "pop-secret-b64u")?;
    let agent_id = arg(args, "agent-id")?;
    let method = arg(args, "method")?.to_uppercase();
    let target_uri = arg(args, "target-uri")?;
    let body_raw = arg_opt(args, "body").unwrap_or_default();
    let body = if body_raw == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("read body from stdin: {e}"))?;
        buf
    } else if let Some(path) = body_raw.strip_prefix('@') {
        fs::read_to_string(path).map_err(|e| format!("read body file {path}: {e}"))?
    } else {
        body_raw
    };
    let tenant_id = arg_opt(args, "tenant").unwrap_or_else(|| "default".to_string());
    let audience = arg_opt(args, "audience").unwrap_or_else(|| "sauron-core".to_string());
    let config_digest = arg_opt(args, "config-digest").unwrap_or_default();
    let content_type = arg_opt(args, "content-type").unwrap_or_else(|| {
        if body.is_empty() {
            String::new()
        } else {
            "application/json".to_string()
        }
    });

    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(pop_secret.trim())
        .map_err(|e| format!("pop-secret-b64u is not base64url: {e}"))?;
    let key_bytes: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| "pop secret must decode to 32 bytes".to_string())?;
    let signing_key = SigningKey::from_bytes(&key_bytes);

    let body_sha256_hex = hex::encode(Sha256::digest(body.as_bytes()));
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis()
        .to_string();
    let nonce = hex::encode(rand_32());

    let payload = call_signature_payload(&CallSignatureInput {
        agent_id: &agent_id,
        tenant_id: &tenant_id,
        audience: &audience,
        method: &method,
        target_uri: &target_uri,
        content_type: &content_type,
        body_sha256_hex: &body_sha256_hex,
        config_digest: &config_digest,
        timestamp_ms: &timestamp_ms,
        nonce: &nonce,
    });
    let sig = signing_key.sign(&payload);
    let sig_b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Ok(json!({
        "x-sauron-agent-id": agent_id,
        "x-sauron-tenant-id": tenant_id,
        "x-sauron-call-audience": audience,
        "x-sauron-call-ts": timestamp_ms,
        "x-sauron-call-nonce": nonce,
        "x-sauron-call-sig": sig_b64u,
        "x-sauron-protocol-version": "2",
        "x-sauron-agent-config-digest": config_digest,
    }))
}

fn rand_32() -> [u8; 32] {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

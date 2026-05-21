//! Integration coverage for `sauron_core::secret_provider`.
//!
//! These tests stand up a tiny in-process HTTP server that mimics Vault's
//! Transit endpoints (`POST /v1/transit/decrypt/<key>` and
//! `POST /v1/transit/encrypt/<key>`). The goal is to exercise the full
//! `resolve_secret` → `VaultTransitClient::decrypt_blocking` path end-to-end
//! without an external Vault binary in CI.
//!
//! Env mutation is process-global; the two tests serialise on a shared mutex
//! so they do not race when run in parallel under `cargo test`.

use sauron_core::secret_provider::{resolve_secret, ResolveError, VaultTransitClient};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Mutex, MutexGuard, OnceLock};

fn env_lock() -> MutexGuard<'static, ()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn clear_vault_env() {
    for k in [
        "SAURON_VAULT_TRANSIT_ENABLED",
        "SAURON_VAULT_ADDR",
        "SAURON_VAULT_TOKEN",
        "SAURON_VAULT_TRANSIT_KEY",
        "SAURON_AWS_KMS_ENABLED",
    ] {
        std::env::remove_var(k);
    }
}

/// Spawn a tiny one-shot HTTP echo server. Reads one request, replies with
/// `response_body` as a JSON 200, then exits.
fn spawn_mock_vault(response_body: String) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);
    let h = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 8192];
        let _ = stream.read(&mut buf);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            len = response_body.len(),
            body = response_body
        );
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.flush();
    });
    (url, h)
}

#[test]
fn vault_transit_end_to_end_resolves_wrapped_root_secret() {
    let _g = env_lock();
    clear_vault_env();

    // base64("token-secret-bytes") = dG9rZW4tc2VjcmV0LWJ5dGVz
    let body = r#"{"data":{"plaintext":"dG9rZW4tc2VjcmV0LWJ5dGVz"}}"#.to_string();
    let (url, h) = spawn_mock_vault(body);

    std::env::set_var("SAURON_VAULT_TRANSIT_ENABLED", "1");
    std::env::set_var("SAURON_VAULT_ADDR", &url);
    std::env::set_var("SAURON_VAULT_TOKEN", "hvs.test");
    std::env::set_var("SAURON_VAULT_TRANSIT_KEY", "sauronid-root");
    std::env::set_var(
        "SAURON_TOKEN_SECRET_INT_WRAPPED",
        "vault:v1:integration-fixture",
    );

    let out = resolve_secret("SAURON_TOKEN_SECRET_INT").expect("decrypt success");
    assert_eq!(out, b"token-secret-bytes");

    std::env::remove_var("SAURON_TOKEN_SECRET_INT_WRAPPED");
    clear_vault_env();
    let _ = h.join();
}

#[test]
fn vault_transit_unreachable_returns_backend_unavailable() {
    let _g = env_lock();
    clear_vault_env();

    // Point at a port that nothing is listening on. reqwest will time out / refuse.
    std::env::set_var("SAURON_VAULT_TRANSIT_ENABLED", "1");
    std::env::set_var("SAURON_VAULT_ADDR", "http://127.0.0.1:1");
    std::env::set_var("SAURON_VAULT_TOKEN", "hvs.test");
    std::env::set_var("SAURON_VAULT_TRANSIT_KEY", "sauronid-root");
    std::env::set_var(
        "SAURON_TOKEN_SECRET_UNREACH_WRAPPED",
        "vault:v1:unreachable",
    );

    let err = resolve_secret("SAURON_TOKEN_SECRET_UNREACH").expect_err("must error");
    assert!(
        matches!(err, ResolveError::BackendUnavailable(_)),
        "expected BackendUnavailable, got: {err:?}"
    );

    std::env::remove_var("SAURON_TOKEN_SECRET_UNREACH_WRAPPED");
    clear_vault_env();
}

#[test]
fn vault_disabled_falls_back_to_plaintext_env() {
    let _g = env_lock();
    clear_vault_env();
    std::env::set_var("SAURON_JWT_SECRET_DEV_PATH", "dev-jwt");

    let out = resolve_secret("SAURON_JWT_SECRET_DEV_PATH").expect("ok");
    assert_eq!(out, b"dev-jwt");

    std::env::remove_var("SAURON_JWT_SECRET_DEV_PATH");
}

#[test]
fn vault_client_from_env_is_none_when_flag_unset() {
    let _g = env_lock();
    clear_vault_env();
    let c = VaultTransitClient::from_env().expect("ok");
    assert!(c.is_none());
}

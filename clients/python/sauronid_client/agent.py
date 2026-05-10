"""Signed agent runtime. Generates the PoP keypair, signs every call.

`SignedAgent.call(method, path, body)` is the only public surface most
operators will use. It produces all five required headers:

  - x-sauron-agent-id
  - x-sauron-call-ts
  - x-sauron-call-nonce
  - x-sauron-call-sig
  - x-sauron-agent-config-digest

and routes the request through the SauronID core.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, List, Mapping, Optional, Sequence

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from .client import SauronIDClient, SauronIDError


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _now_ms() -> int:
    import time
    return int(time.time() * 1000)


def _make_pop_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Generate Ed25519. Returns (private, base64url public-x)."""
    sk = Ed25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk, _b64u(pk_bytes)


def _ed25519_sign(sk: Ed25519PrivateKey, msg: bytes) -> str:
    return _b64u(sk.sign(msg))


@dataclass
class SignedAgent:
    """A registered agent with the keys to sign every outbound call."""

    client: SauronIDClient
    agent_id: str
    config_digest: str
    private_key: Ed25519PrivateKey = field(repr=False)
    intent_scope: List[str] = field(default_factory=list)

    # ─────────────────────────────────────────────────────────────────────

    def call(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Mapping[str, Any]] = None,
        body_bytes: Optional[bytes] = None,
        extra_headers: Optional[Mapping[str, str]] = None,
        skip_sig: bool = False,
    ) -> requests.Response:
        """Make a SauronID-protected HTTP call. Returns the raw Response.

        Either pass `json_body` (will be JSON-encoded with deterministic separators)
        or `body_bytes` (raw bytes). For GET requests pass neither.
        """
        if json_body is not None and body_bytes is not None:
            raise ValueError("pass either json_body or body_bytes, not both")
        if json_body is not None:
            body_bytes = json.dumps(
                json_body, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        if body_bytes is None:
            body_bytes = b""

        headers = dict(extra_headers or {})
        if json_body is not None and "content-type" not in {k.lower() for k in headers}:
            headers["content-type"] = "application/json"

        if not skip_sig:
            sig_headers = self._sign_call_headers(method, path, body_bytes)
            headers.update(sig_headers)

        url = f"{self.client.base_url}{path}"
        return requests.request(
            method, url, headers=headers, data=body_bytes, timeout=self.client.timeout
        )

    def _sign_call_headers(
        self, method: str, path: str, body_bytes: bytes
    ) -> dict:
        ts = _now_ms()
        nonce = secrets.token_hex(16)
        body_hash_hex = hashlib.sha256(body_bytes).hexdigest()
        signing_payload = f"{method.upper()}|{path}|{body_hash_hex}|{ts}|{nonce}".encode(
            "utf-8"
        )
        sig_b64u = _ed25519_sign(self.private_key, signing_payload)
        return {
            "x-sauron-agent-id": self.agent_id,
            "x-sauron-call-ts": str(ts),
            "x-sauron-call-nonce": nonce,
            "x-sauron-call-sig": sig_b64u,
            "x-sauron-agent-config-digest": self.config_digest,
        }

    # ─────────────────────────────────────────────────────────────────────

    def report_egress(
        self,
        target_host: str,
        target_path: str,
        method: str,
        *,
        body_hash_hex: str = "",
        status_code: int = 0,
    ) -> None:
        """Record an outbound call to a third-party API in the SauronID egress log.

        Operators wire their HTTP client wrappers to call this BEFORE every
        outbound request. The log entry is included in the next agent-action
        merkle anchor batch, making after-the-fact tampering require forging
        Bitcoin AND Solana attestations.
        """
        body = {
            "agent_id": self.agent_id,
            "target_host": target_host,
            "target_path": target_path,
            "method": method.upper(),
            "body_hash_hex": body_hash_hex,
            "status_code": status_code,
        }
        body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
        sig_headers = self._sign_call_headers("POST", "/agent/egress/log", body_bytes)
        r = requests.post(
            f"{self.client.base_url}/agent/egress/log",
            headers={"content-type": "application/json", **sig_headers},
            data=body_bytes,
            timeout=self.client.timeout,
        )
        if not r.ok:
            raise SauronIDError(r.status_code, r.text)

    # ─────────────────────────────────────────────────────────────────────

    def revoke(self, user_session: str) -> None:
        r = requests.delete(
            f"{self.client.base_url}/agent/{self.agent_id}",
            headers={"x-sauron-session": user_session},
            timeout=self.client.timeout,
        )
        if not r.ok:
            raise SauronIDError(r.status_code, r.text)


# ─────────────────────────────────────────────────────────────────────────
# Registration helpers — typed inputs per agent kind so the server
# canonicalises and computes the binding checksum.
# ─────────────────────────────────────────────────────────────────────────

def _gen_ring_pair() -> tuple[str, str]:
    """Generate a real Ristretto ring keypair by shelling out to the Rust
    `agent-action-tool keygen` binary. This binary ships in the SauronID
    repo at `core/target/release/agent-action-tool`.

    Returns `(public_key_hex, ring_key_image_hex)`. The secret_hex is also
    returned by the tool but we deliberately discard it — agents that need
    the secret to sign action envelopes should call `agent-action-tool`
    themselves so the secret never crosses Python's heap unnecessarily.

    Override path: if `SAURONID_AGENT_ACTION_TOOL` env var points at a
    binary, use that. Otherwise we look in `$PATH` and finally try the
    repo-local `core/target/release/` directory.

    Pure-Python operators who have not built the Rust binaries can supply
    `public_key_hex` and `ring_key_image_hex` directly to
    `register_*_agent(...)` and skip this helper.
    """
    import os as _os
    import shutil as _shutil
    import subprocess as _subprocess

    candidates = [
        _os.environ.get("SAURONID_AGENT_ACTION_TOOL"),
        _shutil.which("agent-action-tool"),
        _os.path.abspath(
            _os.path.join(
                _os.path.dirname(__file__),
                "..", "..", "..", "core", "target", "release", "agent-action-tool",
            )
        ),
    ]
    binary = next((c for c in candidates if c and _os.path.isfile(c)), None)
    if binary is None:
        raise RuntimeError(
            "Could not locate the `agent-action-tool` binary. Either:\n"
            "  1. Build the SauronID core: `cd core && cargo build --release`\n"
            "  2. Set $SAURONID_AGENT_ACTION_TOOL=/path/to/agent-action-tool\n"
            "  3. Pass `public_key_hex` and `ring_key_image_hex` explicitly to register_*_agent(...)"
        )
    try:
        out = _subprocess.run(
            [binary, "keygen"], check=True, capture_output=True, text=True
        ).stdout
    except _subprocess.CalledProcessError as exc:
        raise RuntimeError(f"agent-action-tool keygen failed: {exc.stderr}") from exc
    data = json.loads(out)
    pk = data["public_key_hex"]
    ring_ki = data["ring_key_image_hex"]
    return pk, ring_ki


def register_llm_agent(
    client: SauronIDClient,
    *,
    user_session: str,
    user_key_image: str,
    model_id: str,
    system_prompt: str,
    tools: Sequence[str],
    public_key_hex: Optional[str] = None,
    ring_key_image_hex: Optional[str] = None,
    intent_scope: Optional[Sequence[str]] = None,
    pop_jkt: Optional[str] = None,
    ttl_secs: int = 3600,
    extra_inputs: Optional[Mapping[str, Any]] = None,
) -> SignedAgent:
    """Register an LLM agent. The model + system_prompt + tool list become
    the binding checksum; flipping any of them at runtime without rotating
    via /agent/<id>/checksum/update will reject every subsequent call.
    """
    sk, pop_b64u = _make_pop_keypair()
    pk_hex, ring_ki = (
        public_key_hex or _gen_ring_pair()[0],
        ring_key_image_hex or _gen_ring_pair()[1],
    )
    intent = list(intent_scope or [])
    inputs: dict = {
        "model_id": model_id,
        "system_prompt": system_prompt,
        "tools": list(tools),
    }
    if extra_inputs:
        inputs.update(extra_inputs)

    body = {
        "human_key_image": user_key_image,
        "agent_type": "llm",
        "checksum_inputs": inputs,
        "agent_checksum": "",  # server computes
        "intent_json": json.dumps({"scope": intent}, separators=(",", ":")),
        "public_key_hex": pk_hex,
        "ring_key_image_hex": ring_ki,
        "pop_jkt": pop_jkt or f"sauronid-py-{secrets.token_hex(8)}",
        "pop_public_key_b64u": pop_b64u,
        "ttl_secs": ttl_secs,
    }
    resp = requests.post(
        f"{client.base_url}/agent/register",
        headers={
            "content-type": "application/json",
            "x-sauron-session": user_session,
        },
        data=json.dumps(body),
        timeout=client.timeout,
    )
    if not resp.ok:
        raise SauronIDError(resp.status_code, resp.text)
    data = resp.json()
    agent_id = data["agent_id"]

    # Read back server-computed digest from agent record.
    rec = client.get_json(f"/agent/{agent_id}")
    digest = rec["agent_checksum"]

    return SignedAgent(
        client=client,
        agent_id=agent_id,
        config_digest=digest,
        private_key=sk,
        intent_scope=intent,
    )


def register_mcp_agent(
    client: SauronIDClient,
    *,
    user_session: str,
    user_key_image: str,
    manifest_json: Mapping[str, Any],
    tool_signatures: Sequence[str],
    public_key_hex: Optional[str] = None,
    ring_key_image_hex: Optional[str] = None,
    intent_scope: Optional[Sequence[str]] = None,
    pop_jkt: Optional[str] = None,
    ttl_secs: int = 3600,
    extra_inputs: Optional[Mapping[str, Any]] = None,
) -> SignedAgent:
    """Register an MCP server-style agent."""
    sk, pop_b64u = _make_pop_keypair()
    pk_hex, ring_ki = (
        public_key_hex or _gen_ring_pair()[0],
        ring_key_image_hex or _gen_ring_pair()[1],
    )
    intent = list(intent_scope or [])
    inputs: dict = {
        "manifest_json": dict(manifest_json),
        "tool_signatures": list(tool_signatures),
    }
    if extra_inputs:
        inputs.update(extra_inputs)
    body = {
        "human_key_image": user_key_image,
        "agent_type": "mcp_server",
        "checksum_inputs": inputs,
        "agent_checksum": "",
        "intent_json": json.dumps({"scope": intent}, separators=(",", ":")),
        "public_key_hex": pk_hex,
        "ring_key_image_hex": ring_ki,
        "pop_jkt": pop_jkt or f"sauronid-py-{secrets.token_hex(8)}",
        "pop_public_key_b64u": pop_b64u,
        "ttl_secs": ttl_secs,
    }
    resp = requests.post(
        f"{client.base_url}/agent/register",
        headers={
            "content-type": "application/json",
            "x-sauron-session": user_session,
        },
        data=json.dumps(body),
        timeout=client.timeout,
    )
    if not resp.ok:
        raise SauronIDError(resp.status_code, resp.text)
    agent_id = resp.json()["agent_id"]
    rec = client.get_json(f"/agent/{agent_id}")
    digest = rec["agent_checksum"]
    return SignedAgent(
        client=client,
        agent_id=agent_id,
        config_digest=digest,
        private_key=sk,
        intent_scope=intent,
    )


def register_custom_agent(
    client: SauronIDClient,
    *,
    user_session: str,
    user_key_image: str,
    inputs: Mapping[str, Any],
    public_key_hex: Optional[str] = None,
    ring_key_image_hex: Optional[str] = None,
    intent_scope: Optional[Sequence[str]] = None,
    pop_jkt: Optional[str] = None,
    ttl_secs: int = 3600,
) -> SignedAgent:
    """Register a custom-type agent. `inputs` is hashed verbatim — operator
    decides what goes in. Recommended fields per docs/threat-model.md.
    """
    sk, pop_b64u = _make_pop_keypair()
    pk_hex, ring_ki = (
        public_key_hex or _gen_ring_pair()[0],
        ring_key_image_hex or _gen_ring_pair()[1],
    )
    intent = list(intent_scope or [])
    body = {
        "human_key_image": user_key_image,
        "agent_type": "custom",
        "checksum_inputs": dict(inputs),
        "agent_checksum": "",
        "intent_json": json.dumps({"scope": intent}, separators=(",", ":")),
        "public_key_hex": pk_hex,
        "ring_key_image_hex": ring_ki,
        "pop_jkt": pop_jkt or f"sauronid-py-{secrets.token_hex(8)}",
        "pop_public_key_b64u": pop_b64u,
        "ttl_secs": ttl_secs,
    }
    resp = requests.post(
        f"{client.base_url}/agent/register",
        headers={
            "content-type": "application/json",
            "x-sauron-session": user_session,
        },
        data=json.dumps(body),
        timeout=client.timeout,
    )
    if not resp.ok:
        raise SauronIDError(resp.status_code, resp.text)
    agent_id = resp.json()["agent_id"]
    rec = client.get_json(f"/agent/{agent_id}")
    return SignedAgent(
        client=client,
        agent_id=agent_id,
        config_digest=rec["agent_checksum"],
        private_key=sk,
        intent_scope=intent,
    )

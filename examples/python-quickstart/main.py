"""SauronID Python quickstart: register, make a signed call, get denied.

Prereqs: `docker compose up` at the repo root, `pip install sauronid-client`,
and the agent-action-tool binary (`cd core && cargo build --release`, or set
SAURONID_AGENT_ACTION_TOOL). See README.md.
"""

import os

from sauronid_client import SauronIDClient, register_llm_agent

CORE_URL = os.environ.get("SAURON_CORE_URL", "http://localhost:3001")
DEV_ADMIN_KEY = os.environ.get("SAURON_ADMIN_KEY", "dev-only-admin-key-not-for-production")  # dev stack only


def main() -> None:
    client = SauronIDClient(base_url=CORE_URL, admin_key=DEV_ADMIN_KEY)

    # 1. Authenticate the human owner (dev-only password login, seeded user).
    auth = client.user_auth("alice@sauron.dev", "pass_alice")
    print(f"user session ok, key_image={auth['key_image'][:16]}...")

    # 2. Register the agent. model + prompt + tools become the binding
    #    checksum; the Ed25519 PoP keypair never leaves this process.
    #    max_amount + currency register a server-enforced payment cap.
    agent = register_llm_agent(
        client,
        user_session=auth["session"],
        user_key_image=auth["key_image"],
        model_id="claude-sonnet-4-5",
        system_prompt="You are a careful assistant.",
        tools=["search"],
        intent_scope=["payment_initiation"],
        max_amount=5.00,
        currency="EUR",
    )
    print(f"registered agent_id={agent.agent_id}")
    print(f"binding checksum  ={agent.config_digest}")

    # 3. A signed call (call-sig v2 headers: ts, nonce, body hash, digest).
    resp = agent.call("GET", f"/agent/{agent.agent_id}")
    record = resp.json()
    print(f"signed call -> {resp.status_code}")
    print(f"server-stored checksum={record['agent_checksum'][:24]}... "
          f"status={record.get('status', '?')}")

    # 4. A deliberately over-limit payment. The intent caps this agent at
    #    5.00 EUR, so the leash denies 2500.00 EUR server-side with the real
    #    "Requested amount ... exceeds intent maxAmount" message (see
    #    docs/site/guides/payments.md).
    denial = agent.authorize_payment(
        user_session=auth["session"],
        amount_minor=250_000,  # 2500.00 EUR
        currency="EUR",
        payment_ref="quickstart-overlimit-001",
    )
    print(f"payment attempt -> {denial.status_code} (expected 403)")
    print(f"denial body: {denial.text}")

    assert denial.status_code == 403, "leash should have denied this payment"

    agent.revoke(auth["session"])
    print("agent revoked")


if __name__ == "__main__":
    main()

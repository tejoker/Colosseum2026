"""Anthropic tool_use dispatch guarded by a SauronID policy.

Runs offline against the dev stack: the tool_use blocks below are dict-shaped
exactly like the Anthropic API returns them, so no API key is needed. In a
real loop they come from
`[b for b in message.content if b.type == "tool_use"]`.

Prereqs: `docker compose up` at the repo root, `pip install sauronid-client`
(add `[anthropic]` when wiring the real API). See README.md.
"""

import os

from sauronid_client import (
    SauronIDClient,
    create_enforcer,
    dispatch_tool_use_blocks,
)

CORE_URL = "http://localhost:3001"
DEV_ADMIN_KEY = os.environ.get("SAURON_ADMIN_KEY", "dev-only-admin-key-not-for-production")

POLICY = """\
version: "1"
agent: example_anthropic_tools
binding:
  allowed_tools: [search]
  max_budget_usd: 25
"""


def search(query: str) -> str:
    return f"3 hits for '{query}'"


def send_payment(amount_usd: float, to: str) -> str:
    return f"sent ${amount_usd} to {to}"


def main() -> None:
    client = SauronIDClient(base_url=CORE_URL, admin_key=DEV_ADMIN_KEY)
    policy_id = client.post_json(
        "/v1/policy/upload", {"raw_yaml": POLICY}, headers=client.admin_headers()
    )["policy_id"]
    print(f"policy uploaded: {policy_id}")

    enf = create_enforcer(
        core_url=CORE_URL,
        admin_key=DEV_ADMIN_KEY,
        policy_id=policy_id,
        agent_id="example-anthropic-tools",
    )

    # One allowed call, one policy-denied call — the exact shape the API emits.
    tool_use_blocks = [
        {"id": "toolu_1", "name": "search",
         "input": {"query": "blue widgets"}},
        {"id": "toolu_2", "name": "send_payment",
         "input": {"amount_usd": 9.5, "to": "acme"}},
    ]

    results = dispatch_tool_use_blocks(
        tool_use_blocks,
        {"search": search, "send_payment": send_payment},
        enforcer=enf,
    )
    # Feed back as the next user message: {"role": "user", "content": results}
    for block in results:
        flag = " (is_error)" if block.get("is_error") else ""
        print(f"{block['tool_use_id']}{flag}: {block['content']}")

    enf.stop()


if __name__ == "__main__":
    main()

"""OpenAI tool-call dispatch guarded by a SauronID policy.

Runs offline against the dev stack: the tool calls below are dict-shaped
exactly like the OpenAI API returns them, so no OpenAI key is needed. In a
real loop they come from `run.required_action.submit_tool_outputs.tool_calls`
(Assistants) or `response.choices[0].message.tool_calls` (chat completions).

Prereqs: `docker compose up` at the repo root, `pip install sauronid-client`
(add `[openai]` when wiring the real API). See README.md.
"""

import os

from sauronid_client import SauronIDClient, create_enforcer, dispatch_tool_calls

CORE_URL = "http://localhost:3001"
DEV_ADMIN_KEY = os.environ.get("SAURON_ADMIN_KEY", "dev-only-admin-key-not-for-production")

POLICY = """\
version: "1"
agent: example_openai_tools
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
        agent_id="example-openai-tools",
    )

    # One allowed call, one policy-denied call — the exact shape the API emits.
    tool_calls = [
        {"id": "call_1", "function": {"name": "search",
                                      "arguments": '{"query": "blue widgets"}'}},
        {"id": "call_2", "function": {"name": "send_payment",
                                      "arguments": '{"amount_usd": 9.5, "to": "acme"}'}},
    ]

    outputs = dispatch_tool_calls(
        tool_calls,
        {"search": search, "send_payment": send_payment},
        enforcer=enf,
    )
    # Ready for client.beta.threads.runs.submit_tool_outputs(..., tool_outputs=outputs)
    for row in outputs:
        print(f"{row['tool_call_id']}: {row['output']}")

    enf.stop()


if __name__ == "__main__":
    main()

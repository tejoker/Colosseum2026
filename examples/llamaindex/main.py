"""LlamaIndex FunctionTools guarded by a SauronID policy.

Prereqs: `docker compose up` at the repo root and
`pip install "sauronid-client[llamaindex]"`. See README.md.
"""

from llama_index.core.tools import FunctionTool

from sauronid_client import SauronIDClient, wrap

CORE_URL = "http://localhost:3001"
DEV_ADMIN_KEY = "dev-only-admin-key-not-for-production"

POLICY = """\
version: "1"
agent: example_llamaindex
binding:
  allowed_tools: [search]
  max_budget_usd: 25
"""


def search(query: str) -> str:
    """Search the product catalog."""
    return f"3 hits for '{query}'"


def send_payment(amount_usd: float, to: str) -> str:
    """Send a payment. Not on the policy allowlist."""
    return f"sent ${amount_usd} to {to}"


def main() -> None:
    client = SauronIDClient(base_url=CORE_URL, admin_key=DEV_ADMIN_KEY)
    policy_id = client.post_json(
        "/v1/policy/upload", {"raw_yaml": POLICY}, headers=client.admin_headers()
    )["policy_id"]
    print(f"policy uploaded: {policy_id}")

    tools = [
        FunctionTool.from_defaults(fn=search),
        FunctionTool.from_defaults(fn=send_payment),
    ]

    # Drop-in replacements: hand `guarded` to an AgentRunner as-is.
    guarded_search, guarded_pay = wrap(
        tools,
        client=client,
        policy_id=policy_id,
        agent_id="example-llamaindex",
    )

    # Allowed: "search" is on the policy allowlist.
    print("search ->", guarded_search.call(query="blue widgets"))

    # Denied: "send_payment" is not allowlisted. The wrapper returns a
    # "Policy denied: ..." string as the tool result, so the agent loop
    # recovers instead of crashing (raise_on_deny=True raises instead).
    print("send_payment ->", guarded_pay.call(amount_usd=9.5, to="acme"))


if __name__ == "__main__":
    main()

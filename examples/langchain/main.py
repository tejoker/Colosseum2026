"""LangChain tools guarded by a SauronID policy.

Prereqs: `docker compose up` at the repo root and
`pip install "sauronid-client[langchain]"`. See README.md.
"""

from langchain_core.tools import tool

from sauronid_client import SauronIDClient, wrap

CORE_URL = "http://localhost:3001"
DEV_ADMIN_KEY = "dev-only-admin-key-not-for-production"

POLICY = """\
version: "1"
agent: example_langchain
binding:
  allowed_tools: [search]
  max_budget_usd: 25
"""


@tool
def search(query: str) -> str:
    """Search the product catalog."""
    return f"3 hits for '{query}'"


@tool
def send_payment(amount_usd: float, to: str) -> str:
    """Send a payment. Not on the policy allowlist."""
    return f"sent ${amount_usd} to {to}"


def main() -> None:
    client = SauronIDClient(base_url=CORE_URL, admin_key=DEV_ADMIN_KEY)
    policy_id = client.post_json(
        "/v1/policy/upload", {"raw_yaml": POLICY}, headers=client.admin_headers()
    )["policy_id"]
    print(f"policy uploaded: {policy_id}")

    # Drop-in replacements: hand `guarded` to an AgentExecutor as-is.
    guarded_search, guarded_pay = wrap(
        [search, send_payment],
        client=client,
        policy_id=policy_id,
        agent_id="example-langchain",
    )

    # Allowed: "search" is on the policy allowlist.
    # (config=None satisfies LangChain's injected-arg signature when calling
    # _run directly; inside an AgentExecutor this is handled for you.)
    print("search ->", guarded_search(query="blue widgets", config=None))

    # Denied: "send_payment" is not allowlisted. The wrapper returns a
    # "Policy denied: ..." string as the tool result, so the agent loop
    # recovers instead of crashing (pass raise_on_deny=True to get the
    # PolicyDeniedError instead).
    print("send_payment ->", guarded_pay(amount_usd=9.5, to="acme", config=None))


if __name__ == "__main__":
    main()

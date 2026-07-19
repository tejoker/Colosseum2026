"""CrewAI tools guarded by a SauronID policy.

Prereqs: `docker compose up` at the repo root and
`pip install "sauronid-client[crewai]"`. See README.md.
"""

from crewai.tools import BaseTool

from sauronid_client import SauronIDClient, wrap

CORE_URL = "http://localhost:3001"
DEV_ADMIN_KEY = "dev-only-admin-key-not-for-production"

POLICY = """\
version: "1"
agent: example_crewai
binding:
  allowed_tools: [search]
  max_budget_usd: 25
"""


class SearchTool(BaseTool):
    name: str = "search"
    description: str = "Search the product catalog."

    def _run(self, query: str) -> str:
        return f"3 hits for '{query}'"


class SendPaymentTool(BaseTool):
    name: str = "send_payment"
    description: str = "Send a payment. Not on the policy allowlist."

    def _run(self, amount_usd: float, to: str) -> str:
        return f"sent ${amount_usd} to {to}"


def main() -> None:
    client = SauronIDClient(base_url=CORE_URL, admin_key=DEV_ADMIN_KEY)
    policy_id = client.post_json(
        "/v1/policy/upload", {"raw_yaml": POLICY}, headers=client.admin_headers()
    )["policy_id"]
    print(f"policy uploaded: {policy_id}")

    # Drop-in replacements: hand `guarded` to crewai.Agent(tools=...) as-is.
    guarded_search, guarded_pay = wrap(
        [SearchTool(), SendPaymentTool()],
        client=client,
        policy_id=policy_id,
        agent_id="example-crewai",
    )

    # Allowed: "search" is on the policy allowlist. CrewAI dispatches via
    # the public run() entry point, which the wrapper preserves.
    print("search ->", guarded_search.run(query="blue widgets"))

    # Denied: "send_payment" is not allowlisted. The wrapper returns a
    # "Policy denied: ..." string as the tool result, so the crew loop
    # recovers instead of crashing (raise_on_deny=True raises instead).
    print("send_payment ->", guarded_pay.run(amount_usd=9.5, to="acme"))


if __name__ == "__main__":
    main()

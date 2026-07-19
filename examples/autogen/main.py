"""AutoGen function tools guarded by a SauronID policy.

Prereqs: `docker compose up` at the repo root and
`pip install "sauronid-client[autogen]"`. See README.md.
"""

import autogen

from sauronid_client import SauronIDClient, create_enforcer, guard_functions

CORE_URL = "http://localhost:3001"
DEV_ADMIN_KEY = "dev-only-admin-key-not-for-production"

POLICY = """\
version: "1"
agent: example_autogen
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

    enf = create_enforcer(
        core_url=CORE_URL,
        admin_key=DEV_ADMIN_KEY,
        policy_id=policy_id,
        agent_id="example-autogen",
    )
    # The mapping key is the LLM-facing tool name the policy evaluates.
    guarded = guard_functions(
        {"search": search, "send_payment": send_payment}, enf
    )

    # Register the guarded callables exactly like the originals — metadata
    # (__name__, __doc__, signature) is preserved for schema generation.
    executor = autogen.ConversableAgent("executor", llm_config=False,
                                        human_input_mode="NEVER")
    for name, fn in guarded.items():
        executor.register_for_execution(name=name)(fn)

    # Allowed: "search" is on the policy allowlist.
    print("search ->", guarded["search"](query="blue widgets"))

    # Denied: "send_payment" is not allowlisted. The wrapper returns a
    # "Policy denied: ..." string as the tool result, so the conversation
    # recovers instead of crashing (raise_on_deny=True raises instead).
    print("send_payment ->", guarded["send_payment"](amount_usd=9.5, to="acme"))

    enf.stop()


if __name__ == "__main__":
    main()

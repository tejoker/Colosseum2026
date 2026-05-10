"""SauronID Python client.

Sign and route every AI-agent call through SauronID. Works with any agent
runtime — LangChain, OpenAI Assistants, Anthropic Computer Use, MCP servers,
plain `requests` — by wrapping the tool-call execution layer.

Quick example:

    from sauronid_client import SauronIDClient, register_llm_agent

    client = SauronIDClient(base_url="https://sauronid.your-co.internal",
                            admin_key="…")
    agent = register_llm_agent(
        client,
        user_session=...,                        # opaque from /user/auth
        model_id="claude-opus-4-7",
        system_prompt=open("prompt.md").read(),
        tools=["search", "fetch"],
    )
    # agent.private_key never leaves the process; agent.config_digest is
    # what the server stored as agents.agent_checksum.

    # Use anywhere you'd normally do `requests.post(...)`:
    resp = agent.call("POST", "/internal/api/search",
                       json={"query": "Anthropic claude opus 4.7 docs"})
    # SauronID has signed, replay-protected, body-bound, intent-leashed,
    # config-digest-checked the call. Audit row is anchored to BTC + Solana.
"""

from .client import SauronIDClient, SauronIDError
from .agent import (
    SignedAgent,
    register_llm_agent,
    register_mcp_agent,
    register_custom_agent,
)
from .adapters import (
    LangChainTool,
    wrap_openai_tool_call,
    wrap_anthropic_tool_use,
)

__version__ = "0.1.0"
__all__ = [
    "SauronIDClient",
    "SauronIDError",
    "SignedAgent",
    "register_llm_agent",
    "register_mcp_agent",
    "register_custom_agent",
    "LangChainTool",
    "wrap_openai_tool_call",
    "wrap_anthropic_tool_use",
]

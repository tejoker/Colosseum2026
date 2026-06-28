#!/usr/bin/env python3
"""SauronID Agent Runner — backs the dashboard "Agent Console".

A tiny stdlib HTTP service (no extra deps beyond the sauronid_client venv) that
runs REAL, Sauron-bound LLM agents on demand:

  POST /run        {model, prompt}           -> register a bound agent, let it do
                                                the task with a web_fetch tool
                                                (gemma on the local GPU, or Groq),
                                                every call signed + egress-logged.
                                                Returns the transcript + answer.
  POST /misbehave  {agent_id, kind}          -> make that SAME agent try something
                                                bad (replay / tamper / revoked) and
                                                report how the core BLOCKED it.
  GET  /agents                               -> list agents this runner created.
  GET  /health

Runs on the GPU box (reaches local Ollama + Groq + the cloud core). The
dashboard reaches it over a reverse SSH tunnel — no public GPU port.

Env:
  SAURON_CORE_URL              cloud core base URL (https://core.<...>.sslip.io)
  SAURON_ADMIN_KEY             admin key (matches the core)
  SAURONID_AGENT_ACTION_TOOL   path to agent-action-tool (Ristretto keygen)
  OLLAMA_HOST                  default localhost:11434
  GROQ_API_KEY                 for the Groq model (optional)
  RUNNER_PORT                  default 8765
  DEMO_USER_EMAIL/PASSWORD     default alice@sauron.dev / pass_alice
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

from sauronid_client import SauronIDClient, register_llm_agent
from sauronid_client.agent import _gen_ring_pair

CORE = os.environ["SAURON_CORE_URL"].rstrip("/")
ADMIN_KEY = os.environ["SAURON_ADMIN_KEY"]
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "localhost:11434")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
PORT = int(os.environ.get("RUNNER_PORT", "8765"))
EMAIL = os.environ.get("DEMO_USER_EMAIL", "alice@sauron.dev")
PASSWORD = os.environ.get("DEMO_USER_PASSWORD", "pass_alice")

# Per-model wire config. Both speak the OpenAI Chat Completions API.
MODELS = {
    "gemma": {
        "label": "gemma4:e4b (local · 4060Ti)",
        "url": f"http://{OLLAMA_HOST}/v1/chat/completions",
        "model_id": os.environ.get("OLLAMA_MODEL", "gemma4:e4b"),
        "host": OLLAMA_HOST.split(":")[0],
        "auth": "ollama",  # ignored by Ollama
    },
    "groq": {
        "label": "llama-3.3-70b (Groq cloud)",
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "model_id": "llama-3.3-70b-versatile",
        "host": "api.groq.com",
        "auth": GROQ_API_KEY,
    },
}

SYSTEM_PROMPT = (
    "You are a capable web research agent. You have two tools:\n"
    "  • web_search(query): search the web, returns titles, URLs and snippets.\n"
    "  • web_fetch(url): open a page and return its readable text.\n"
    "Work step by step: for a question like finding the cheapest product, first "
    "web_search for it, then web_fetch the most promising result pages, compare "
    "what you find, and follow links / search again if needed. Use several steps. "
    "When you have enough, give a clear final answer with the key facts (e.g. the "
    "price and where it's from). Only state things the tools actually returned — "
    "never invent prices, URLs, or facts."
)
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web. Returns a list of {title, url, snippet}.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_fetch",
            "description": "Open a URL and return its readable text (HTML stripped).",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
]

# agent_id -> {"agent": SignedAgent, "model": str, "session": str, "key_image": str}
_AGENTS: dict = {}
_LOCK = threading.Lock()


TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY", "")
UA = {"user-agent": "Mozilla/5.0 (compatible; sauron-agent/1.0)"}


def _truncate(s: str, n: int = 6000) -> str:
    return s if len(s) <= n else s[:n] + f"\n…[truncated {len(s) - n} chars]"


def _html_to_text(html: str) -> str:
    """Strip HTML to readable text so the model sees content, not tag soup."""
    try:
        from bs4 import BeautifulSoup  # type: ignore
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript", "svg", "header", "footer", "nav"]):
            tag.decompose()
        text = soup.get_text(" ", strip=True)
    except Exception:
        import re
        text = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
        text = re.sub(r"(?s)<[^>]+>", " ", text)
    import re as _re
    return _re.sub(r"\s+", " ", text).strip()


def _assert_public_url(url: str) -> None:
    """M-4 SSRF guard: only http(s) to a publicly-routable host. Blocks
    loopback / private / link-local (incl. the 169.254.169.254 cloud-metadata
    endpoint) / reserved / multicast across every resolved IP.

    Residual: DNS rebinding between this check and the request, and redirect
    targets, are not fully closed — we disable redirects in `web_fetch` and
    re-validate is left as a hardening TODO for non-demo use.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"blocked URL scheme {parsed.scheme!r} (only http/https allowed)")
    host = parsed.hostname
    if not host:
        raise ValueError("URL has no host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for {host!r}: {e}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise ValueError(f"blocked non-public address {ip} for host {host!r}")


def web_fetch(url: str) -> str:
    try:
        _assert_public_url(url)
        # Redirects disabled so a public URL can't bounce the request to an
        # internal/metadata target after the SSRF check.
        r = requests.get(url, timeout=15, headers=UA, allow_redirects=False)
        if r.is_redirect or r.is_permanent_redirect:
            return f"web_fetch blocked: refusing to follow redirect to {r.headers.get('location', '?')}"
        ctype = r.headers.get("content-type", "")
        body = r.text if "html" in ctype or "<html" in r.text[:200].lower() else r.text
        return _truncate(_html_to_text(body) if "<" in body else body)
    except ValueError as e:
        return f"web_fetch blocked (SSRF guard): {e}"
    except requests.RequestException as e:
        return f"web_fetch error: {e}"


def web_search(query: str, max_results: int = 6) -> str:
    """Web search. Uses Tavily when TAVILY_API_KEY is set, else DuckDuckGo HTML."""
    if TAVILY_API_KEY:
        try:
            r = requests.post("https://api.tavily.com/search", timeout=20, json={
                "api_key": TAVILY_API_KEY, "query": query,
                "max_results": max_results, "include_answer": False,
            })
            res = r.json().get("results", [])
            lines = [f"{i+1}. {x.get('title','')}\n   {x.get('url','')}\n   {(x.get('content') or '')[:300]}"
                     for i, x in enumerate(res[:max_results])]
            return "\n".join(lines) or "no results"
        except requests.RequestException as e:
            return f"web_search error (tavily): {e}"
    # No-key fallback: DuckDuckGo HTML endpoint.
    try:
        r = requests.post("https://html.duckduckgo.com/html/", timeout=20,
                          headers=UA, data={"q": query})
        from bs4 import BeautifulSoup  # type: ignore
        soup = BeautifulSoup(r.text, "html.parser")
        out = []
        for res in soup.select(".result")[: max_results * 2]:
            a = res.select_one(".result__a")
            sn = res.select_one(".result__snippet")
            if not a:
                continue
            href = a.get("href", "")
            # DDG wraps links as /l/?uddg=<encoded>
            q = urllib.parse.urlparse(href).query
            real = urllib.parse.parse_qs(q).get("uddg", [href])[0]
            out.append(f"{len(out)+1}. {a.get_text(' ', strip=True)}\n   {real}\n   "
                       f"{(sn.get_text(' ', strip=True) if sn else '')[:300]}")
            if len(out) >= max_results:
                break
        return "\n".join(out) or "no results"
    except Exception as e:  # noqa: BLE001
        return f"web_search error: {e}"


def _exec_tool(agent, search_host: str, name: str, args: dict, steps: list) -> str:
    if name == "web_search":
        query = str(args.get("query", ""))
        steps.append({"type": "tool_call", "tool": "web_search", "url": query})
        try:
            agent.report_egress(search_host, "/search", "POST", status_code=0)
        except Exception as e:  # noqa: BLE001
            steps.append({"type": "egress_error", "detail": str(e)})
        return web_search(query)
    url = str(args.get("url", ""))
    parsed = urllib.parse.urlparse(url)
    steps.append({"type": "tool_call", "tool": "web_fetch", "url": url})
    try:
        agent.report_egress(parsed.hostname or "", parsed.path or "/", "GET", status_code=0)
    except Exception as e:  # noqa: BLE001
        steps.append({"type": "egress_error", "detail": str(e)})
    return web_fetch(url)


def _recover_tool_calls(body_text: str) -> list:
    """Groq's llama sometimes emits `<function=name {json}</function>` and the
    API returns 400 tool_use_failed. Parse the intended call(s) so we recover."""
    import re
    try:
        err = json.loads(body_text).get("error", {})
        if err.get("code") != "tool_use_failed":
            return []
        gen = err.get("failed_generation", "") or ""
    except Exception:  # noqa: BLE001
        return []
    out = []
    for m in re.finditer(r"<function=(\w+)\s*(\{.*?\})\s*</function>", gen, re.DOTALL):
        try:
            out.append((m.group(1), json.loads(m.group(2))))
        except Exception:  # noqa: BLE001
            out.append((m.group(1), {}))
    return out


def run_agent(model: str, prompt: str) -> dict:
    cfg = MODELS.get(model)
    if not cfg:
        raise ValueError(f"unknown model '{model}'")
    if model == "groq" and not GROQ_API_KEY:
        raise ValueError("GROQ_API_KEY not set on the runner")

    client = SauronIDClient(base_url=CORE, admin_key=ADMIN_KEY)
    auth = client.user_auth(EMAIL, PASSWORD)
    pk_hex, ring_ki = _gen_ring_pair()
    agent = register_llm_agent(
        client,
        user_session=auth["session"],
        user_key_image=auth["key_image"],
        model_id=cfg["model_id"],
        system_prompt=SYSTEM_PROMPT,
        tools=["web_search", "web_fetch"],
        public_key_hex=pk_hex,
        ring_key_image_hex=ring_ki,
        intent_scope=["llm.invoke", "tool.web_search", "tool.web_fetch"],
        ttl_secs=3600,
    )

    steps: list = []
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]
    sess = requests.Session()
    sess.headers.update(
        {"authorization": f"Bearer {cfg['auth']}", "content-type": "application/json"}
    )
    search_host = "api.tavily.com" if TAVILY_API_KEY else "html.duckduckgo.com"
    answer = None
    for turn in range(8):
        body = {
            "model": cfg["model_id"],
            "messages": messages,
            "tools": TOOLS,
            "tool_choice": "auto",
            "temperature": 0,
        }
        body_bytes = json.dumps(body, separators=(",", ":")).encode()
        # Leash: every outbound LLM call is signed + egress-logged before it goes.
        try:
            agent.report_egress(cfg["host"], "/v1/chat/completions", "POST",
                                status_code=0)
        except Exception as e:  # noqa: BLE001
            steps.append({"type": "egress_error", "detail": str(e)})
        steps.append({"type": "llm_call", "to": cfg["host"], "turn": turn + 1})
        r = sess.post(cfg["url"], data=body_bytes, timeout=90)
        if not r.ok:
            recovered = _recover_tool_calls(r.text) if r.status_code == 400 else []
            if recovered:
                # Model emitted a malformed tool call — execute the intended one
                # and feed the result back so it can continue.
                for i, (name, args) in enumerate(recovered):
                    out = _exec_tool(agent, search_host, name, args, steps)
                    cid = f"recover_{turn}_{i}"
                    messages.append({"role": "assistant", "content": None, "tool_calls": [
                        {"id": cid, "type": "function",
                         "function": {"name": name, "arguments": json.dumps(args)}}]})
                    messages.append({"role": "tool", "tool_call_id": cid, "content": out})
                continue
            steps.append({"type": "llm_error", "status": r.status_code,
                          "detail": _truncate(r.text, 300)})
            break
        choice = r.json()["choices"][0]["message"]
        tool_calls = choice.get("tool_calls") or []
        if not tool_calls:
            answer = choice.get("content") or ""
            steps.append({"type": "answer", "text": answer})
            break
        messages.append(choice)
        for tc in tool_calls:
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except Exception:  # noqa: BLE001
                args = {}
            out = _exec_tool(agent, search_host, tc["function"].get("name", "web_fetch"), args, steps)
            messages.append({
                "role": "tool",
                "tool_call_id": tc.get("id", "call_0"),
                "content": out,
            })

    with _LOCK:
        _AGENTS[agent.agent_id] = {
            "agent": agent, "model": model, "label": cfg["label"],
            "session": auth["session"], "key_image": auth["key_image"],
        }
    return {
        "agent_id": agent.agent_id,
        "model": model,
        "model_label": cfg["label"],
        "config_digest": agent.config_digest,
        "steps": steps,
        "answer": answer,
    }


def misbehave(agent_id: str, kind: str) -> dict:
    """Each attack runs against the LIVE core. We return BOTH the legitimate
    call the core accepted (200) and the attack it rejected (4xx) so the UI can
    show the contrast — a mock could never accept-then-block the same agent."""
    with _LOCK:
        rec = _AGENTS.get(agent_id)
    if not rec:
        raise ValueError("unknown agent_id (run a task first)")
    agent = rec["agent"]
    url = f"{CORE}/agent/egress/log"
    endpoint = f"{urllib.parse.urlparse(CORE).netloc}/agent/egress/log"

    def _body(path: str) -> bytes:
        return json.dumps({
            "agent_id": agent.agent_id, "target_host": "api.merchant-demo.example",
            "target_path": path, "method": "POST", "body_hash_hex": "", "status_code": 0,
        }, separators=(",", ":")).encode()

    def _send(b: bytes, headers: dict) -> int:
        r = requests.post(url, headers={"content-type": "application/json", **headers},
                          data=b, timeout=10)
        return r.status_code

    def out(kind, accepted, blocked_status, reason):
        return {"kind": kind, "blocked": blocked_status in (401, 403, 409),
                "accepted_status": accepted, "blocked_status": blocked_status,
                "status_code": blocked_status, "endpoint": endpoint, "reason": reason}

    if kind == "replay":
        b = _body("/charge/ok")
        h = agent._sign_call_headers("POST", "/agent/egress/log", b)
        accepted = _send(b, h)            # legit signed call → core accepts
        blocked = _send(b, h)             # identical replay → core rejects
        return out("replay", accepted, blocked,
                   "the exact same signed request, sent twice — the core's single-use "
                   "nonce accepted the first and rejected the replay")

    if kind == "tamper":
        ok_b = _body("/charge/ok")
        accepted = _send(ok_b, agent._sign_call_headers("POST", "/agent/egress/log", ok_b))
        b = _body("/charge/ok2")
        h = agent._sign_call_headers("POST", "/agent/egress/log", b)
        tampered = b.replace(b"/charge/ok2", b"/charge/EVIL-DRAINED")
        blocked = _send(tampered, h)      # body changed after signing → 401
        return out("tamper", accepted, blocked,
                   "a valid call is accepted; when the body is altered after signing, "
                   "the body-hash no longer matches and the core rejects it")

    if kind == "revoked":
        ok_b = _body("/charge/ok")
        accepted = _send(ok_b, agent._sign_call_headers("POST", "/agent/egress/log", ok_b))
        try:
            agent.revoke(rec["session"])
        except Exception:  # noqa: BLE001
            pass
        b = _body("/charge/after-revoke")
        blocked = _send(b, agent._sign_call_headers("POST", "/agent/egress/log", b))
        return out("revoked", accepted, blocked,
                   "the agent's calls are accepted — until it's revoked, after which "
                   "the core refuses every call")

    raise ValueError(f"unknown misbehavior '{kind}'")


class Handler(BaseHTTPRequestHandler):
    def _json(self, code: int, obj: dict) -> None:
        payload = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_a):  # quiet
        pass

    def _read(self) -> dict:
        n = int(self.headers.get("content-length", "0") or "0")
        if not n:
            return {}
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"ok": True, "models": list(MODELS)})
        if self.path == "/agents":
            with _LOCK:
                out = [{"agent_id": k, "model": v["model"], "label": v["label"]}
                       for k, v in _AGENTS.items()]
            return self._json(200, {"agents": out})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        try:
            data = self._read()
            if self.path == "/run":
                return self._json(200, run_agent(str(data.get("model", "gemma")),
                                                 str(data.get("prompt", "")).strip()))
            if self.path == "/misbehave":
                return self._json(200, misbehave(str(data.get("agent_id", "")),
                                                 str(data.get("kind", ""))))
            self._json(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            self._json(500, {"error": str(e)})


if __name__ == "__main__":
    print(f"agent-runner on :{PORT}  core={CORE}  models={list(MODELS)}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

# OpenAI tool-call dispatch

Policy-enforces the OpenAI tool-call dispatch loop: `search` executes,
`send_payment` yields a `"Policy denied: ..."` tool output the model can
recover from. Uses dict-shaped tool calls, so it runs without an OpenAI key.

## Prereqs

- `docker compose up` at the repo root.
- `pip install sauronid-client` (add `"sauronid-client[openai]"` when
  wiring the real API).

## Run

```bash
python3 main.py
```

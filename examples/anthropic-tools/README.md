# Anthropic tool_use dispatch

Policy-enforces the Anthropic tool-use loop: `search` executes,
`send_payment` yields an `is_error` tool_result with
`"Policy denied: ..."` so the model can recover. Uses dict-shaped blocks,
so it runs without an Anthropic key.

## Prereqs

- `docker compose up` at the repo root.
- `pip install sauronid-client` (add `"sauronid-client[anthropic]"` when
  wiring the real API).

## Run

```bash
python3 main.py
```

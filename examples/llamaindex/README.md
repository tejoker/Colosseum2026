# LlamaIndex adapter

Wraps LlamaIndex `FunctionTool`s so every call is checked against a SauronID
policy: `search` is allowed, `send_payment` comes back as a
`"Policy denied: ..."` tool result.

## Prereqs

- `docker compose up` at the repo root.
- `pip install "sauronid-client[llamaindex]"`

## Run

```bash
python3 main.py
```

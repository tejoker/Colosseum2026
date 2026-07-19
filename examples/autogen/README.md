# AutoGen adapter

Guards plain callables before they are registered with AutoGen agents:
`search` is allowed, `send_payment` comes back as a
`"Policy denied: ..."` tool result.

## Prereqs

- `docker compose up` at the repo root.
- `pip install "sauronid-client[autogen]"`

## Run

```bash
python3 main.py
```

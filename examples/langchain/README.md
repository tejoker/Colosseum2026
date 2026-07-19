# LangChain adapter

Wraps LangChain tools so every call is checked against a SauronID policy:
`search` is allowed, `send_payment` comes back as a
`"Policy denied: ..."` tool result.

## Prereqs

- `docker compose up` at the repo root.
- `pip install "sauronid-client[langchain]"`

## Run

```bash
python3 main.py
```

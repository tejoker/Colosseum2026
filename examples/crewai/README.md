# CrewAI adapter

Wraps CrewAI `BaseTool`s so every `run()` is checked against a SauronID
policy: `search` is allowed, `send_payment` comes back as a
`"Policy denied: ..."` tool result.

## Prereqs

- `docker compose up` at the repo root.
- `pip install "sauronid-client[crewai]"`

## Run

```bash
python3 main.py
```

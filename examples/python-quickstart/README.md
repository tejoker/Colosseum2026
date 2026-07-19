# Python quickstart

Register an agent, make a signed call, watch the leash deny an over-limit
payment.

## Prereqs

- `docker compose up` at the repo root (core on `http://localhost:3001`).
- `pip install sauronid-client` (or `pip install -e ../../clients/python`).
- Ring keygen binary: `cd ../../core && cargo build --release`, or set
  `SAURONID_AGENT_ACTION_TOOL=/path/to/agent-action-tool`.

## Run

```bash
python3 main.py
```

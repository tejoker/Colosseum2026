# Python quickstart

Register an agent, make a signed call, watch the leash deny an over-limit
payment.

## Two scripts

- `main.py` — register an agent, make a signed call, watch the leash deny an
  over-limit payment. Uses the seeded demo user and a password: the fast path.
- `owner_mandate.py` — the stronger property. The owner's Ed25519 key is
  generated locally and never leaves the process; the server stores only its
  public half. The script then tries, as the operator would, to register an
  agent with authority the owner never signed for, and shows it refused:

  ```
  operator tries max 1,000,000 EUR -> 401
    owner mandate signature does not verify against the owner key bound to human_key_image
  owner's actual grant             -> 200
  ```

  Run it when the question is "why should I trust the party running this?".

  Two modes, same code path:

  - **Demo** — the seed gives each demo user a throwaway owner key. Copy them out
    and the script runs as `alice@sauron.dev`:

    ```bash
    docker compose exec -T backend \
      cat /var/lib/sauronid/demo-owner-keys.json > demo-owner-keys.json
    python examples/python-quickstart/owner_mandate.py
    ```

  - **Real** — with no key file present it registers a fresh owner and generates
    the key in-process, which is what a production owner does. The server cannot
    tell the difference; only the disposability of the key differs.

## Prereqs

- `docker compose up` at the repo root (core on `http://localhost:3001`).
- `pip install sauronid-client` (or `pip install -e ../../clients/python`).
- Ring keygen binary: `cd ../../core && cargo build --release`, or set
  `SAURONID_AGENT_ACTION_TOOL=/path/to/agent-action-tool`.

## Run

```bash
python3 main.py
```

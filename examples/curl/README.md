# curl leash tour

No SDK, just curl: health check, dev user registration, session login, and
denied-vs-allowed calls showing the 4xx error envelope
(`{"error":{"code","message","fix"}}`).

## Prereqs

- `docker compose up` at the repo root (dev endpoints and the fixed dev
  admin key are only present in the dev stack).

## Run

```bash
bash leash.sh
```
